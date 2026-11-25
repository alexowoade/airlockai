import { sha256Hex } from "@airlock/core";

export interface MerkleProofStep {
  readonly position: "left" | "right";
  readonly hash: string;
}

export interface MerkleInclusionProof {
  readonly algorithm: "SHA-256-MERKLE-V1";
  readonly leafIndex: number;
  readonly totalLeaves: number;
  readonly treeDepth: number;
  readonly leafReceiptSha256: string;
  readonly leafNodeHash: string;
  readonly merkleRoot: string;
  readonly proofPath: ReadonlyArray<MerkleProofStep>;
}

export interface MerkleTreeSnapshot {
  readonly root: string | null;
  readonly leafCount: number;
  readonly depth: number;
  readonly levels: ReadonlyArray<ReadonlyArray<string>>;
  readonly orderedReceiptHashes: ReadonlyArray<string>;
}

const LEAF_DOMAIN = "airlock.merkle.leaf.v1:";
const NODE_DOMAIN = "airlock.merkle.node.v1:";

export async function hashMerkleLeaf(receiptSha256: string): Promise<string> {
  return sha256Hex(`${LEAF_DOMAIN}${receiptSha256}`);
}

export async function hashMerkleNode(leftHash: string, rightHash: string): Promise<string> {
  return sha256Hex(`${NODE_DOMAIN}${leftHash}:${rightHash}`);
}

/**
 * Builds a canonical domain-separated SHA-256 binary Merkle tree from chronological
 * receiptSha256 hashes (oldest -> newest). Odd levels duplicate the trailing node.
 */
export async function buildMerkleTree(
  chronologicalReceiptHashes: ReadonlyArray<string>
): Promise<MerkleTreeSnapshot> {
  const leafCount = chronologicalReceiptHashes.length;
  if (leafCount === 0) {
    return {
      root: null,
      leafCount: 0,
      depth: 0,
      levels: [],
      orderedReceiptHashes: [],
    };
  }

  const leafLevel = await Promise.all(chronologicalReceiptHashes.map((h) => hashMerkleLeaf(h)));
  const levels: string[][] = [leafLevel];

  let current = leafLevel;
  while (current.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i]!;
      const right = current[i + 1] ?? left;
      next.push(await hashMerkleNode(left, right));
    }
    levels.push(next);
    current = next;
  }

  return {
    root: current[0] ?? null,
    leafCount,
    depth: Math.max(0, levels.length - 1),
    levels,
    orderedReceiptHashes: [...chronologicalReceiptHashes],
  };
}

/**
 * Generates an O(log N) selective-disclosure inclusion proof for a single leaf index
 * without revealing any other receipt bodies in the ledger.
 */
export function generateMerkleInclusionProof(
  tree: MerkleTreeSnapshot,
  leafIndex: number
): MerkleInclusionProof | null {
  if (!tree.root || leafIndex < 0 || leafIndex >= tree.leafCount) {
    return null;
  }

  const proofPath: MerkleProofStep[] = [];
  let idx = leafIndex;

  for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
    const nodes = tree.levels[lvl]!;
    const isRightChild = idx % 2 === 1;
    const siblingIdx = isRightChild ? idx - 1 : Math.min(idx + 1, nodes.length - 1);
    proofPath.push({
      position: isRightChild ? "left" : "right",
      hash: nodes[siblingIdx]!,
    });
    idx = Math.floor(idx / 2);
  }

  return {
    algorithm: "SHA-256-MERKLE-V1",
    leafIndex,
    totalLeaves: tree.leafCount,
    treeDepth: tree.depth,
    leafReceiptSha256: tree.orderedReceiptHashes[leafIndex]!,
    leafNodeHash: tree.levels[0]![leafIndex]!,
    merkleRoot: tree.root,
    proofPath,
  };
}

/**
 * Independently verifies an O(log N) Merkle inclusion proof offline.
 */
export async function verifyMerkleInclusionProof(
  proof: MerkleInclusionProof
): Promise<{ readonly ok: boolean; readonly computedRoot: string; readonly detail: string }> {
  const computedLeaf = await hashMerkleLeaf(proof.leafReceiptSha256);
  if (computedLeaf !== proof.leafNodeHash) {
    return {
      ok: false,
      computedRoot: computedLeaf,
      detail: "MERKLE LEAF MISMATCH: leafReceiptSha256 does not hash to leafNodeHash.",
    };
  }

  let acc = computedLeaf;
  for (const step of proof.proofPath) {
    acc =
      step.position === "left"
        ? await hashMerkleNode(step.hash, acc)
        : await hashMerkleNode(acc, step.hash);
  }

  const ok = acc === proof.merkleRoot;
  return {
    ok,
    computedRoot: acc,
    detail: ok
      ? `MERKLE INCLUSION VERIFIED (Leaf #${proof.leafIndex + 1}/${proof.totalLeaves}, ${proof.proofPath.length} O(log N) sibling hash(es) -> Root ${acc.slice(0, 14)}…).`
      : `MERKLE ROOT MISMATCH: Computed root (${acc.slice(0, 14)}…) != attested root (${proof.merkleRoot.slice(0, 14)}…).`,
  };
}
