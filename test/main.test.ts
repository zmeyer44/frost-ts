import { Point, Participant, Aggregator, Q, G } from "../index";

describe("FROST Tests", () => {
  let p1: Participant, p2: Participant, p3: Participant;

  beforeEach(() => {
    p1 = new Participant(1, 2, 3);
    p2 = new Participant(2, 2, 3);
    p3 = new Participant(3, 2, 3);

    // Round 1.1, 1.2, 1.3, and 1.4
    p1.initKeygen();
    p2.initKeygen();
    p3.initKeygen();

    // Round 2.1
    p1.generateShares();
    p2.generateShares();
    p3.generateShares();
    if (!p1.shares || !p2.shares || !p3.shares) {
      throw new Error("Unable to create shares");
    }

    // Round 2.3
    p1.aggregateShares([p2.shares[p1.index - 1]!, p3.shares[p1.index - 1]!]);
    p2.aggregateShares([p1.shares[p2.index - 1]!, p3.shares[p2.index - 1]!]);
    p3.aggregateShares([p1.shares[p3.index - 1]!, p2.shares[p3.index - 1]!]);
    if (!p1.aggregateShare || !p2.aggregateShare || !p3.aggregateShare) {
      throw new Error("Unable to create aggregateShare");
    }
    if (
      !p1.coefficientCommitments ||
      !p2.coefficientCommitments ||
      !p3.coefficientCommitments
    ) {
      throw new Error("Unable to create coefficientCommitments");
    }
    // Round 2.4
    p1.derivePublicKey([
      p2.coefficientCommitments[0]!,
      p3.coefficientCommitments[0]!,
    ]);
    p2.derivePublicKey([
      p1.coefficientCommitments[0]!,
      p3.coefficientCommitments[0]!,
    ]);
    p3.derivePublicKey([
      p1.coefficientCommitments[0]!,
      p2.coefficientCommitments[0]!,
    ]);

    const pk1 = p1.publicKey;
    const pk2 = p2.publicKey;
    const pk3 = p3.publicKey;

    expect(pk1).toEqual(pk2);
    expect(pk2).toEqual(pk3);

    p1.deriveGroupCommitments([
      p2.coefficientCommitments,
      p3.coefficientCommitments,
    ]);
    p2.deriveGroupCommitments([
      p1.coefficientCommitments,
      p3.coefficientCommitments,
    ]);
    p3.deriveGroupCommitments([
      p1.coefficientCommitments,
      p2.coefficientCommitments,
    ]);

    const groupCommitments1 = p1.groupCommitments!;
    const groupCommitments2 = p2.groupCommitments!;
    const groupCommitments3 = p3.groupCommitments!;

    expect(groupCommitments1).toEqual(groupCommitments2);
    expect(groupCommitments2).toEqual(groupCommitments3);

    expect(
      p1.verifyShare(p1.aggregateShare, groupCommitments1, 2),
    ).toBeTruthy();
    expect(
      p2.verifyShare(p2.aggregateShare, groupCommitments1, 2),
    ).toBeTruthy();
    expect(
      p3.verifyShare(p3.aggregateShare, groupCommitments1, 2),
    ).toBeTruthy();
  });

  test("keygen", () => {
    if (!p1.aggregateShare || !p2.aggregateShare || !p3.aggregateShare) {
      throw new Error("Unable to create aggregateShare");
    }
    // Round 1.5
    expect(
      p1.verifyProofOfKnowledge(
        p2.proofOfKnowledge!,
        p2.coefficientCommitments![0]!,
        2,
      ),
    ).toBeTruthy();
    expect(
      p1.verifyProofOfKnowledge(
        p3.proofOfKnowledge!,
        p3.coefficientCommitments![0]!,
        3,
      ),
    ).toBeTruthy();

    expect(
      p2.verifyProofOfKnowledge(
        p1.proofOfKnowledge!,
        p1.coefficientCommitments![0]!,
        1,
      ),
    ).toBeTruthy();
    expect(
      p2.verifyProofOfKnowledge(
        p3.proofOfKnowledge!,
        p3.coefficientCommitments![0]!,
        3,
      ),
    ).toBeTruthy();

    expect(
      p3.verifyProofOfKnowledge(
        p1.proofOfKnowledge!,
        p1.coefficientCommitments![0]!,
        1,
      ),
    ).toBeTruthy();
    expect(
      p3.verifyProofOfKnowledge(
        p2.proofOfKnowledge!,
        p2.coefficientCommitments![0]!,
        2,
      ),
    ).toBeTruthy();

    // Round 2.2
    expect(
      p1.verifyShare(p2.shares![p1.index - 1]!, p2.coefficientCommitments!, 2),
    ).toBeTruthy();
    expect(
      p1.verifyShare(p3.shares![p1.index - 1]!, p3.coefficientCommitments!, 2),
    ).toBeTruthy();

    expect(
      p2.verifyShare(p1.shares![p2.index - 1]!, p1.coefficientCommitments!, 2),
    ).toBeTruthy();
    expect(
      p2.verifyShare(p3.shares![p2.index - 1]!, p3.coefficientCommitments!, 2),
    ).toBeTruthy();

    expect(
      p3.verifyShare(p1.shares![p3.index - 1]!, p1.coefficientCommitments!, 2),
    ).toBeTruthy();
    expect(
      p3.verifyShare(p2.shares![p3.index - 1]!, p2.coefficientCommitments!, 2),
    ).toBeTruthy();

    // Reconstruct secret
    const pk1 = p1.publicKey;

    let l1 = p1._lagrangeCoefficient([2]);
    let l2 = p2._lagrangeCoefficient([1]);
    let secret = (p1.aggregateShare * l1 + p2.aggregateShare * l2) % Q;
    if (!secret) {
      throw new Error("Unable to generate secret");
    }
    expect(G.multiply(secret)).toEqual(pk1);

    l1 = p1._lagrangeCoefficient([3]);
    let l3 = p3._lagrangeCoefficient([1]);
    secret = (p1.aggregateShare * l1 + p3.aggregateShare * l3) % Q;
    expect(G.multiply(secret)).toEqual(pk1);

    l2 = p2._lagrangeCoefficient([3]);
    l3 = p3._lagrangeCoefficient([2]);
    secret = (p2.aggregateShare * l2 + p3.aggregateShare * l3) % Q;
    expect(G.multiply(secret)).toEqual(pk1);

    l1 = p1._lagrangeCoefficient([2, 3]);
    l2 = p2._lagrangeCoefficient([1, 3]);
    l3 = p3._lagrangeCoefficient([1, 2]);
    secret =
      (p1.aggregateShare * l1 +
        p2.aggregateShare * l2 +
        p3.aggregateShare * l3) %
      Q;
    expect(G.multiply(secret)).toEqual(pk1);
  });

  test("sign", () => {
    const pk = p1.publicKey!;

    // NonceGen
    p1.generateNoncePair();
    p2.generateNoncePair();
    p3.generateNoncePair();

    // Sign
    const msg = Buffer.from("fnord!");
    const participantIndexes = [1, 2];
    const agg = new Aggregator(
      pk,
      msg,
      [p1.nonceCommitmentPair!, p2.nonceCommitmentPair!],
      participantIndexes,
    );
    const [message, nonceCommitmentPairs] = agg.signingInputs();

    const s1 = p1.sign(message, nonceCommitmentPairs, participantIndexes);
    const s2 = p2.sign(message, nonceCommitmentPairs, participantIndexes);

    // σ = (R, z)
    const sig = agg.signature([s1, s2]);
    const nonceCommitment = Point.xonlyDeserialize(sig.slice(0, 32));

    const z = BigInt(`0x${sig.slice(32).toString("hex")}`);

    // verify
    // c = H_2(R, Y, m)
    const challengeHash = Aggregator.challengeHash(nonceCommitment, pk, msg);
    // Negate Y if Y.y is odd
    let negatedPk = pk.y! % 2n !== 0n ? pk.negate() : pk;

    // R ≟ g^z * Y^-c
    expect(nonceCommitment).toEqual(
      G.multiply(z).add(negatedPk.multiply(Q - challengeHash)),
    );
  });
});
