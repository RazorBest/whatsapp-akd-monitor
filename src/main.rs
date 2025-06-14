extern crate queues;

use queues::*;

use std::error::Error;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value};
//use plexi_core::deserialize_signature_response;

use akd::AzksElement;
use akd::AzksValue;
use akd::Configuration;
use akd::NodeLabel;
use akd::SingleAppendOnlyProof;
use akd::append_only_zks::InsertMode;
use akd::local_auditing::{AuditBlob, AuditBlobName};
use akd::tree_node::NodeKey;
use akd::tree_node::TreeNode;
use akd::tree_node::TreeNodeWithPreviousValue;
use akd::storage::types::DbRecord;

const LOG_FILE: &str = "history_logs.txt";
const PROOFS_STORE_DIR: &str = "stored_proofs";
const PROOFS_META_FILE: &str = "data.json";

fn search_last_epoch(audits_url: &String, root_epoch: u64, max_epoch: u64) -> Result<u64, Box<dyn Error>> {
    let mut left_epoch = root_epoch;
    let mut right_epoch = max_epoch;
    // Perform a binary search to find the last available epoch
    while left_epoch < right_epoch {
        let mid_epoch = left_epoch + (right_epoch - left_epoch) / 2 + (right_epoch - left_epoch) % 2;

        let url = format!("{}/{}", audits_url, mid_epoch);
        let response = reqwest::blocking::get(&url)?;
        if response.status() == reqwest::StatusCode::OK {
            left_epoch = mid_epoch;
        } else {
            right_epoch = mid_epoch - 1;
        }
    }

    Ok(left_epoch)
}

#[derive(Serialize, Deserialize)]
struct ProofMeta {
    epoch: u64,
    previous_hash: [u8; 32],
    current_hash: [u8; 32],
}

impl ProofMeta {
    fn from_audit_blob(audit_blob: &AuditBlob) -> Self {
        Self{
            epoch: audit_blob.name.epoch,
            previous_hash: audit_blob.name.previous_hash,
            current_hash: audit_blob.name.current_hash,
        }
    }

    fn to_audit_blob(&self, data: Vec<u8>) -> AuditBlob {
        AuditBlob{
            name: AuditBlobName{
                epoch: self.epoch,
                previous_hash: self.previous_hash,
                current_hash: self.current_hash,
            },
            data: data,
        }
    }
}

struct ProofStorage {
    proofs_info: HashMap<u64, ProofMeta>,
}

impl ProofStorage {
    fn read_storage_meta() -> Result<HashMap<u64, ProofMeta>, Box<dyn Error>> {
        let info_path = Path::new(PROOFS_STORE_DIR).join(PROOFS_META_FILE);
        let text = fs::read_to_string(info_path)?;
        Ok(serde_json::from_str(&text)?)
    }

    fn new() -> Self {
        Self{proofs_info: ProofStorage::read_storage_meta().unwrap_or_default()}
    }

    fn append_proof_info(&mut self, epoch: u64, proof_info: ProofMeta) {
        self.proofs_info.insert(epoch, proof_info);
    }

    fn get_proof_info_at_epoch(&self, epoch: u64) -> Option<&ProofMeta> {
        self.proofs_info.get(&epoch)
    }

    fn store_proofs_info(&mut self) -> Result<(), Box<dyn Error>> {
        let info_path = Path::new(PROOFS_STORE_DIR).join(PROOFS_META_FILE);
        let text = serde_json::to_string(&self.proofs_info).unwrap();
        fs::write(info_path, text)?;
        Ok(())
    }

    fn stored_file_name_for_audit_proof(&self, epoch: u64) -> String{
        format!("proof_wt_{}", epoch)
    }

    fn store_audit_blob(&mut self, audit_blob: &AuditBlob) -> Result<(), Box<dyn Error>> {
        let epoch = audit_blob.name.epoch;
        let _ = fs::create_dir_all(PROOFS_STORE_DIR);
        let file_name = self.stored_file_name_for_audit_proof(epoch);
        let file_path = Path::new(PROOFS_STORE_DIR).join(file_name);
        let mut store_file = fs::File::create(file_path)?;
        let _ = store_file.write_all(&audit_blob.data);


        let proof_info = ProofMeta::from_audit_blob(audit_blob);
        self.append_proof_info(epoch, proof_info);
        self.store_proofs_info()?;

        Ok(())
    }

    fn read_audit_blob(&self, epoch: u64) -> Option<AuditBlob> {
        let proof_info = self.get_proof_info_at_epoch(epoch)?;

        let _ = fs::create_dir_all(PROOFS_STORE_DIR);
        let file_name = self.stored_file_name_for_audit_proof(proof_info.epoch);
        let file_path = Path::new(PROOFS_STORE_DIR).join(file_name);
        let data: Vec<u8> = fs::read(file_path).ok()?;

        Some(proof_info.to_audit_blob(data))
    }
}


#[derive(Clone)]
struct AuditInfo {
    timestamp: u64,
    epoch: u64,
    digest: String,
}

struct LocalAuditor<'a> {
    audits_url: &'a String,
    log_directory: &'a String,
    audits: HashMap<u64, AuditInfo>,
    proofs: HashMap<u64, AuditBlob>,
    proof_storage: ProofStorage,
}

impl LocalAuditor<'_> {
    fn new<'a>(audits_url: &'a String, log_directory: &'a String) -> LocalAuditor<'a> {
        LocalAuditor{
            audits_url,
            log_directory,
            audits: HashMap::new(),
            proofs: HashMap::new(),
            proof_storage: ProofStorage::new(),
        }
    }

    fn _get_metadata_at_epoch_no_cache(&self, epoch: u64) -> Result<AuditInfo, Box<dyn Error>> {
        let url = format!("{}/{}", self.audits_url, epoch);
        let text = reqwest::blocking::get(&url)?.text()?;
        let data: Value = serde_json::from_str(&text)?;

        let timestamp = data["timestamp"].as_u64().unwrap();
        let epoch = data["epoch"].as_u64().unwrap();
        let digest = String::from(data["digest"].as_str().unwrap());

        Ok(AuditInfo{
            timestamp,
            epoch,
            digest,
        })
    }

    fn get_metadata_at_epoch(&mut self, epoch: u64) -> Result<&AuditInfo, Box<dyn Error>> {
        if !self.audits.contains_key(&epoch)  {
            let audit_info = self._get_metadata_at_epoch_no_cache(epoch)?;
            self.audits.insert(epoch, audit_info);
        }

        Ok(self.audits.get(&epoch).unwrap())
    }

    fn _get_audit_blob_at_epoch_from_internet(&mut self, epoch: u64) -> Result<AuditBlob, Box<dyn Error>> {
        let curr_epoch = self.get_metadata_at_epoch(epoch).unwrap();
        let current_hash = curr_epoch.digest.clone();
        let prev_epoch = self.get_metadata_at_epoch(epoch - 1).unwrap();
        let previous_hash = prev_epoch.digest.clone();

        // Reversed engineered by looking at https://d1tfr3x7n136ak.cloudfront.net/
        let key_id = format!("{}/{}/{}", epoch, previous_hash, current_hash);
        let proof_url = format!("{}/{}", self.log_directory, key_id);
        let proof = reqwest::blocking::get(&proof_url)?.bytes()?;

        println!("Proof length: {}", proof.len());

        let blob_name = AuditBlobName::try_from(key_id.as_str()).map_err(|_e| "Failed building blob")?;
        let blob_name = match AuditBlobName::try_from(key_id.as_str()) {
            Ok(value) => value,
            Err(_e) => {
                println!("Proof url: {}", &proof_url);
                return Err("Error parsing proof".into());
            }
        };
        
        let audit_blob = AuditBlob {
            name: blob_name,
            data: proof.into_iter().collect(),
        };

        self.proof_storage.store_audit_blob(&audit_blob)?;

        Ok(audit_blob)
    }

    fn get_audit_blob_at_epoch(&mut self, epoch: u64) -> Result<AuditBlob, Box<dyn Error>> {
        if self.proofs.contains_key(&epoch)  {
            return Ok(self.proofs.get(&epoch).unwrap().clone());
        }

        if let Some(audit_blob) = self.proof_storage.read_audit_blob(epoch) {
            return Ok(audit_blob);
        }

        let audit_blob = self._get_audit_blob_at_epoch_from_internet(epoch)?;
        self.proofs.insert(epoch, audit_blob.clone());

        Ok(audit_blob)
    }
}

struct AzksDb {
    manager: akd::storage::StorageManager<akd::storage::memory::AsyncInMemoryDatabase>,
    azks: akd::Azks,
}

impl AzksDb {
    async fn new<TC: Configuration>() -> Result<AzksDb, Box<dyn Error>> {
        let db = akd::storage::memory::AsyncInMemoryDatabase::new();
        let manager = akd::storage::StorageManager::new_no_cache(db);
        let azks = akd::Azks::new::<TC, _>(&manager).await?;

        Ok(AzksDb{
            manager,
            azks,
        })
    }

    async fn add_only_unchanged_nodes_proof<TC: Configuration>(&mut self, proof: &SingleAppendOnlyProof) -> Result<(), Box<dyn Error>> {
        self.azks.batch_insert_nodes::<TC, _>(
            &self.manager,
            proof.unchanged_nodes.clone(),
            InsertMode::Auditor,
        ).await?;

        Ok(())
    }

    async fn add_single_append_only_proof<TC: Configuration>(&mut self, epoch: u64, proof: &SingleAppendOnlyProof) -> Result<(), Box<dyn Error>> {
        self.azks.batch_insert_nodes::<TC, _>(
            &self.manager,
            proof.unchanged_nodes.clone(),
            InsertMode::Auditor,
        ).await?;

        self.azks.latest_epoch = epoch - 1;
        let updated_inserted = proof
            .inserted
            .iter()
            .map(|x| {
                let mut y = *x;
                y.value = AzksValue(TC::hash_leaf_with_commitment(x.value, epoch).0);
                y
            })
            .collect();
        self.azks.batch_insert_nodes::<TC, _>(
            &self.manager,
            updated_inserted,
            InsertMode::Auditor,
        )
        .await?;

        Ok(())
    }

    async fn get_node(&self, label: NodeLabel) -> Result<Option<TreeNodeWithPreviousValue>, Box<dyn Error>> {
        let stored_node = self.manager
                .get::<TreeNodeWithPreviousValue>(&NodeKey(label))
                .await?;

        
        let node = match stored_node {
            DbRecord::TreeNode(node) => node,
            _ => return Ok(None),
        };

        Ok(Some(node))
    }
}

struct EpochComputedStats {
    new_inserted_nodes_count: u64,
    inserted_nodes_count: u64,
    old_nodes_count: u64,
}

struct EpochStats {
    computed: EpochComputedStats,
    audit_info: AuditInfo,
}

async fn check_tree_hashes<TC: Configuration>(azks_db: &AzksDb, proof: SingleAppendOnlyProof) -> Result<bool, Box<dyn Error>> {
    let mut values_hm: HashMap<NodeLabel, AzksValue> = HashMap::new();
    for azks_elem in proof.unchanged_nodes.iter().chain(proof.inserted.iter()) {
        values_hm.insert(azks_elem.label, azks_elem.value);
    }

    let root = azks_db.get_node(NodeLabel::root()).await?.unwrap();

    let mut q: Queue<TreeNode> = queue![];

    q.add(root.latest_node)?;

    while q.size() > 0 {
        let node = q.remove()?;
        //let node = azks_db.get_node(node_label).await?.unwrap();

        let left_opt = (async || Some(azks_db.get_node(node.left_child?).await.ok()?.unwrap().latest_node)) ().await;
        let right_opt = (async || Some(azks_db.get_node(node.right_child?).await.ok()?.unwrap().latest_node)) ().await;

        match (&left_opt, &right_opt) {
            (Some(left), Some(right)) => {
                //let computed = TC::compute_parent_hash_from_children(&left.hash, &left.label.label_val, &right.hash, &right.label.label_val);
                //let left_value = AzksValue(TC::hash_leaf_with_commitment(left.hash, left.last_epoch).0);
                //let right_value = AzksValue(TC::hash_leaf_with_commitment(right.hash, right.last_epoch).0);
                let left_value = left.hash;
                let right_value = right.hash;
                let computed = TC::compute_parent_hash_from_children(
                    &left_value,
                    &left.label.value::<TC>(),
                    &right_value,
                    &right.label.value::<TC>(),
                );

                if computed != node.hash {
                    println!("Failed at {}", node.label);
                    println!("Computed {computed:?}");
                    println!("Expected {:?}", node.hash);
                    println!("Left hash {:?}", left_value);
                    println!("Right hash {:?}", right_value);
                    println!("Left label {:?}", left.label);
                    println!("Right label {:?}", right.label);
                    return Ok(false)
                }
            },
            // Node should be leaf in this case
            _ => {
                match values_hm.remove(&node.label) {
                    Some(found) => {
                        if found != node.hash {
                            println!("Hashes differ");
                            return Ok(false);
                        }
                    },
                    None => {
                        println!("Leaf label not found");
                        return Ok(false);
                    }
                }
            },
        }

        if left_opt.is_some() {
            q.add(left_opt.unwrap())?;
        }

        if right_opt.is_some() {
            q.add(right_opt.unwrap())?;
        }
    }

    if values_hm.is_empty() {
        println!("There were still values");
        return Ok(false);
    }

    Ok(true)
}

async fn traverse_tree(azks_db: &AzksDb, node: TreeNode) -> Result<(), Box<dyn Error>> {
    let mut q: Queue<NodeLabel> = queue![];

    q.add(node.label)?;

    while q.size() > 0 {
        let node_label = q.remove()?;
        let node = azks_db.get_node(node_label).await?.unwrap();

        println!("VLabel: {}", node_label);
        println!("VValue: {:?}", node.latest_node.hash);

        if let Some(next_label) = node.latest_node.left_child {
            q.add(next_label)?;
        }
        if let Some(next_label) = node.latest_node.right_child {
            q.add(next_label)?;
        }
    }

    Ok(())
}

async fn process_azks(epoch: u64, prev_hash: [u8; 32], curr_hash: [u8; 32],
                      proof: SingleAppendOnlyProof, proof2: SingleAppendOnlyProof,
                      ) -> Result<EpochComputedStats, Box<dyn Error>> {

    let mut hm: HashMap<NodeLabel, &AzksValue> = HashMap::new();
    let mut hm2: HashMap<&AzksValue, NodeLabel> = HashMap::new();

    for azks_elem in &proof2.unchanged_nodes {
        hm.insert(azks_elem.label, &azks_elem.value);
        hm2.insert(&azks_elem.value, azks_elem.label);
    }

    for azks_elem in &proof2.inserted {
        hm.insert(azks_elem.label, &azks_elem.value);
        hm2.insert(&azks_elem.value, azks_elem.label);
    }

    for azks_elem in &proof.inserted {
        if azks_elem.label.label_len != 256 {
            println!("{}", azks_elem.label.label_len);
        }
        if hm.contains_key(&azks_elem.label) {
            println!("Label present");
        }
        if hm2.contains_key(&azks_elem.value) {
            //println!("Value present");
        }
    }

    /*
    let mut count = 0;
    for azks_elem in &proof2.unchanged_nodes {
        println!("peak2 {}", azks_elem.label);
        if azks_elem.label.label_len == 256 {
            println!("value {:?}", azks_elem.value);
        }
        count += 1;
        if count > 100 {
            break;
        }
    }

    count = 0;
    for azks_elem in &proof.inserted {
        println!("new  {}", azks_elem.label);
        if azks_elem.label.label_len == 256 {
            println!("value {:?}", azks_elem.value);
        }
        count += 1;
        if count > 10 {
            break;
        }
    }

    if hm2.get(&proof.inserted[0].value).is_some() {
        println!("First present");
    }
    if hm2.get(&proof.inserted[1].value).is_some() {
        println!("Second present");
    }
    */

    let mut new_elems: Vec<&AzksElement> = Vec::new();

    for azks_elem in &proof.inserted {
        match hm.get(&azks_elem.label) {
            Some(&&found_value) => {
                if azks_elem.value != found_value {
                    //new_elems.push(&azks_elem);
                }
            },
            None => {
                match hm2.get(&azks_elem.value) {
                    Some(&found_key) => {
                        //println!("{:?}", azks_elem);
                        //println!("Actual {:?}", found_key);
                    },
                    _ => {
                        new_elems.push(azks_elem);
                    }
                }
            },
        }
    }

    println!("New elements: {}/{}", new_elems.len(), proof.inserted.len());

    return Ok(EpochComputedStats {
        new_inserted_nodes_count: new_elems.len() as u64,
        inserted_nodes_count: proof.inserted.len() as u64,
        old_nodes_count: proof.unchanged_nodes.len() as u64,
    });

    type TC = akd::WhatsAppV1Configuration;
    let mut azks_db = AzksDb::new::<TC>().await?;
    let mut azks_db2 = AzksDb::new::<TC>().await?;

    azks_db.add_only_unchanged_nodes_proof::<TC>(&proof).await?;
    azks_db2.add_single_append_only_proof::<TC>(epoch - 1, &proof2).await?;

    /*
    if !check_tree_hashes::<TC>(&azks_db2, proof2).await? {
        println!("Tree is incorrect");
    }
    */


    let root1 = azks_db.get_node(NodeLabel::root()).await?.unwrap();
    let root2 = azks_db2.get_node(NodeLabel::root()).await?.unwrap();

    println!("Root value: {:?}", root1.latest_node.hash);
    println!("Prev Root value: {:?}", root2.latest_node.hash);

    let left1 = azks_db.get_node(root1.latest_node.left_child.unwrap()).await?.unwrap();
    let left2 = azks_db2.get_node(root2.latest_node.left_child.unwrap()).await?.unwrap();

    println!("Left value: {:?}", left1.latest_node.hash);
    println!("Prev Left value: {:?}", left2.latest_node.hash);

    // Test some node
    //let mut rng = rand::rng();
    //let test_node = proof.inserted[(rng.random::<u32>() as usize) % proof.inserted.len()];
    //let test_node = proof.unchanged_nodes[(rng.random::<u32>() as usize) % proof.unchanged_nodes.len()];
    let test_node = proof.unchanged_nodes[0];
    //let test_node = new_elems[0];
    println!("Label: {}", test_node.label);
    println!("Value: {:?}", test_node.value);

    let node_res = azks_db.get_node(test_node.label).await;
    println!("This node: {:?}", node_res);
    let node_s = node_res?.unwrap();

    println!("This node label: {}", node_s.latest_node.label);
    println!("This node value: {:?}", node_s.latest_node.hash);
    println!("Left: {:?}", node_s.latest_node.left_child);
    println!("Right: {:?}", node_s.latest_node.right_child);
    if node_s.previous_node.is_some() {
        println!("This node previous: {}", node_s.previous_node.unwrap().label);
    } else {
        println!("This node previous: None");
    }

    let node2 = azks_db2.get_node(test_node.label).await?.unwrap();
    println!("Other node latest: {}", node2.latest_node.label);
    println!("Other node value: {:?}", node2.latest_node.hash);
    println!("Other Left: {:?}", node2.latest_node.left_child);
    println!("Other Right: {:?}", node2.latest_node.right_child);
    if node2.previous_node.is_some() {
        println!("Other node previous: {}", node2.previous_node.unwrap().label);
    } else {
        println!("Other node previous: None");
    }

    traverse_tree(&azks_db, node_s.latest_node).await?;
    println!("--------------------------------------------\n");
    traverse_tree(&azks_db2, node2.latest_node).await?;

    println!("Done");
    
    let root = azks_db.get_node(NodeLabel::root()).await?.unwrap();
    
    let mut q: Queue<NodeLabel> = queue![];

    q.add(root.label)?;

    let mut count = 0;

    while q.size() > 0 {
        let node_label = q.remove()?;
        let node = azks_db.get_node(node_label).await?.unwrap();

        let mut is_leaf = true;

        if let Some(next_label) = node.latest_node.left_child {
            q.add(next_label)?;
            is_leaf = false;
        }
        if let Some(next_label) = node.latest_node.right_child {
            q.add(next_label)?;
            is_leaf = false;
        }

        if is_leaf {
            count += 1
        }
    }

    println!("Visited leaves: {}", count);

    println!("Root: {:?}", root);

    Ok(EpochComputedStats {new_inserted_nodes_count: 0, inserted_nodes_count: 0, old_nodes_count: 0})
}


fn run_azks(epoch: u64, prev_hash: [u8; 32], curr_hash: [u8; 32], proof: SingleAppendOnlyProof,
            proof2: SingleAppendOnlyProof,
            ) -> Result<EpochComputedStats, Box<dyn Error>> {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(process_azks(epoch, prev_hash, curr_hash, proof, proof2));

    result
}

fn main() -> Result<(), Box<dyn Error>> {
    let cloudflare_url_base = "https://plexi.key-transparency.cloudflare.com";
    let cloudflare_url = "https://plexi.key-transparency.cloudflare.com/namespaces";
    let whatsapp_namespace = "whatsapp.key-transparency.v1";
    let max_expected_epoch = 10000000000u64;
    let resp = reqwest::blocking::get(cloudflare_url)?.text()?;

    println!("{resp}");

    let v: Value = serde_json::from_str(&resp)?;

    let namespace = match &v["namespaces"] {
        Value::Array(arr) => {
            arr.iter().find(|&x| x["name"] == whatsapp_namespace).ok_or_else(|| Box::<dyn Error>::from("Namespace not found"))?
        }
        _ => return Err("Data format error: namespaces key not found".into()),
    };

    let log_directory = String::from(namespace["log_directory"].as_str().unwrap());
    let root = namespace["root"].as_str().unwrap();
    let audits_path = namespace["audits_uri"].as_str().unwrap();
    let audits_url = format!("{}{}", cloudflare_url_base, audits_path);

    let mut auditor = LocalAuditor::new(&audits_url, &log_directory);

    let (root_epoch, _) = root.split_once("/").unwrap();
    let mut curr_epoch = search_last_epoch(&audits_url, root_epoch.parse::<u64>()?, max_expected_epoch)?;
    // It takes some time for the proofs to be uploaded, so don't check really the last epochs
    curr_epoch -= 2;

    let mut stats = vec![];

    let end = curr_epoch - 11;
    while curr_epoch > end {
        println!("Getting proof at epoch {curr_epoch}");
        let audit_blob = auditor.get_audit_blob_at_epoch(curr_epoch)?;
        let (epoch, prev_hash, curr_hash, local_proof) = audit_blob.decode().map_err(|_e| "Error")?;

        println!("Getting proof at epoch {}", curr_epoch - 1);
        let prev_audit_blob = auditor.get_audit_blob_at_epoch(curr_epoch - 1)?;
        let (_epoch, _prev_hash, _curr_hash, local_proof2) = prev_audit_blob.decode().map_err(|_e| "Error")?;

        let computed_stats = run_azks(epoch, prev_hash, curr_hash, local_proof, local_proof2)?;

        let audit_metadata = auditor.get_metadata_at_epoch(curr_epoch)?;

        stats.push(EpochStats {computed: computed_stats, audit_info: audit_metadata.clone()});

        //println!("Timestamp: {}", audit_meta.timestamp);
        /*
        println!("Audit blob epoch: {epoch}");
        println!("New nodes: {}", local_proof.inserted.len());
        println!("Unchanged nodes: {}\n", local_proof.unchanged_nodes.len());
        */

        curr_epoch -= 1;
    }

    Ok(())
}
