extern crate digest;
extern crate sha2;

use digest::Digest
use sha2::Sha256;

const LEAF_SIG: u8 = 0u8;
const INTERNAL_SIG: u8 = 1u8;

type Hash = Vec<u8>;

/// Returns next closest power of 2.
pub fn next_power_of_2(n: usize) -> usize {
    let mut v = n;
    v -= 1;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v += 1;
    v
}

trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

impl AsBytes for &str {
    fn as_bytes(&self) -> &[u8] {
        str::as_bytes(self)
    }
}

impl AsBytes for String {
    fn as_bytes(&self) -> &[u8] {
        String::as_bytes(self)
    }
}

impl AsBytes for Vec<u8> {
    fn as_bytes(&self) -> &[u8] {
        self
    }
}

fn hash_leaf<T, H>(value: &T, hasher: &mut H) -> Hash
where
    H: Digest,
    T: AsBytes,
{
    hasher.update(&[LEAF_SIG]);
    hasher.update(value.as_bytes());
    hasher.finalize_reset().to_vec()
}

fn hash_internal_node<H>(left: &Hash, right: Option<&Hash>, hasher: &mut H) -> Hash
where
    H: Digest,
{
    hasher.update(&[INTERNAL_SIG]);
    hasher.update(left);
    if let Some(r) = right {
        hasher.update(r);
    } else {
        hasher.update(left);
    }
    hasher.finalize_reset().to_vec()
}

fn build_upper_level<H>(nodes: &[Hash], hasher: &mut H) -> Vec<Hash>
where
    H: Digest,
{
    let mut result = Vec::with_capacity((nodes.len() + 1) / 2);
    let mut i = 0;

    while i < nodes.len() {
        if i + 1 < nodes.len() {
            result.push(hash_internal_node(&nodes[i], Some(&nodes[i + 1]), hasher));
            i += 2;
        } else {
            result.push(hash_internal_node(&nodes[i], None, hasher));
            i += 1;
        }
    }

    if result.len() > 1 && result.len() % 2 != 0 {
        let last_node = result.last().unwrap().clone();
        result.push(last_node);
    }

    result
}

fn build_internal_nodes<H>(nodes: &mut [Hash], count_internal_nodes: usize, hasher: &mut H)
where
    H: Digest,
{
    let mut parents = build_upper_level(&nodes[count_internal_nodes..], hasher);
    let mut upper_level_start = count_internal_nodes - parents.len();
    let mut upper_level_end = count_internal_nodes;

    nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);

    while parents.len() > 1 {
        parents = build_upper_level(&parents, hasher);
        upper_level_end = upper_level_start;
        upper_level_start -= parents.len();
        nodes[upper_level_start..upper_level_end].clone_from_slice(&parents);
    }

    nodes[0] = parents.remove(0);
}

struct MerkleTree<H> {
    hasher: H,
    nodes: Vec<Hash>,
    count_internal_nodes: usize,
    count_leaves: usize,
}

impl<H: Digest> MerkleTree<H> {
    fn build_with_hasher<T>(values: &[T], mut hasher: H) -> MerkleTree<H>
    where
        T: AsBytes,
    {
        let count_leaves = values.len();
        assert!(
            count_leaves > 1,
            format!("expected more then 1 value, received {}", count_leaves)
        );

        let leaves: Vec<Hash> = values.iter().map(|v| hash_leaf(v, &mut hasher)).collect();

        let count_leaves = leaves.len();
        let count_internal_nodes = next_power_of_2(count_leaves);
        let mut nodes = vec![Vec::new(); count_internal_nodes + count_leaves];

        nodes[count_internal_nodes..].clone_from_slice(&leaves);

        build_internal_nodes(&mut nodes, count_internal_nodes, &mut hasher);

        MerkleTree {
            hasher: hasher,
            nodes: nodes,
            count_internal_nodes: count_internal_nodes,
            count_leaves: count_leaves,
        }
    }

    pub fn verify<T>(&mut self, position: usize, value: &T) -> bool
    where
        T: AsBytes,
    {
        assert!(
            position < self.count_leaves,
            "position does not relate to any leaf"
        );

        self.nodes[self.count_internal_nodes + position].as_slice()
            == hash_leaf(value, &mut self.hasher).as_slice()
    }

    fn root_hash(&self) -> &Hash {
        &self.nodes[0]
    }
}

fn main() {
    let block = "Hello World";
    let t = MerkleTree::build_with_hasher(&[block, block], Sha256::new());

    assert!(t.root_hash().len() > 0);
    println!("Hello, world!");

    let block1 = "Hello World";
    let block2 = "Bye, bye";
    let mut p = MerkleTree::build_with_hasher(&[block1, block2], Sha256::new());

    assert!(p.verify(0, &block1));
    assert!(p.verify(1, &block2));
}
