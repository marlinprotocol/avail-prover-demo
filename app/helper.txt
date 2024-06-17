program helper.aleo;

record balance:
    owner as address.private;
    amount as u64.private;


mapping account:
	key as address.public;
	value as u64.public;

function mint_private:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as balance.record;
    output r2 as balance.record;


function mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    cast r0 r1 into r2 as balance.record;
    async mint_public r0 r1 into r3;
    output r2 as balance.record;
    output r3 as helper.aleo/mint_public.future;

finalize mint_public:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] r1 into r2;
    add r2 r1 into r3;
    set r3 into account[r0];


function verify_balance:
    input r0 as address.public;
    async verify_balance r0 into r1;
    output r1 as helper.aleo/verify_balance.future;

finalize verify_balance:
    input r0 as address.public;
    get.or_use account[r0] 0u64 into r1;
    assert.neq r1 0u64;


function transfer_relayer_private:
    input r0 as u64.private;
    input r1 as balance.record;
    assert.eq r0 1u64;
    sub r1.amount r0 into r2;
    cast aleo1va0hzrcsj569gz0gd0mvue7xk54vku626nsmvl86s7j490x7yupq89l82z r0 into r3 as balance.record;
    cast r1.owner r2 into r4 as balance.record;
    output r3 as balance.record;
    output r4 as balance.record;


function transfer_relayer:
    input r0 as address.public;
    input r1 as u64.public;
    assert.eq r1 1u64;
    async transfer_relayer r0 aleo1va0hzrcsj569gz0gd0mvue7xk54vku626nsmvl86s7j490x7yupq89l82z r1 into r2;
    output r2 as helper.aleo/transfer_relayer.future;

finalize transfer_relayer:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;
    get.or_use account[r0] 0u64 into r3;
    sub r3 r2 into r4;
    set r4 into account[r0];
    get.or_use account[r1] 0u64 into r5;
    add r5 r2 into r6;
    set r6 into account[r1];
