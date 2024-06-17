import helper.aleo;
import fees.aleo;
program multi_txn_t1.aleo;

record balance:
    owner as address.private;
    amount as u64.private;


mapping account:
	key as address.public;
	value as u64.public;

function transfer_public:
    input r0 as address.public;
    input r1 as u64.public;
    input r2 as u64.public;
    add r1 r2 into r3;
    call helper.aleo/mint_public self.caller r3 into r4 r5;
    call helper.aleo/verify_balance self.caller into r6;
    call helper.aleo/transfer_relayer self.caller 1u64 into r7;
    call fees.aleo/fees 1u64 into r8;
    cast r0 r1 into r9 as balance.record;
    async transfer_public r5 r6 r7 r8 self.caller r0 r1 into r10;
    output r9 as balance.record;
    output r10 as multi_txn_t1.aleo/transfer_public.future;

finalize transfer_public:
    input r0 as helper.aleo/mint_public.future;
    input r1 as helper.aleo/verify_balance.future;
    input r2 as helper.aleo/transfer_relayer.future;
    input r3 as fees.aleo/fees.future;
    input r4 as address.public;
    input r5 as address.public;
    input r6 as u64.public;
    await r0;
    await r1;
    await r2;
    await r3;
    get.or_use account[r4] 0u64 into r7;
    sub r7 r6 into r8;
    set r8 into account[r4];
    get.or_use account[r5] 0u64 into r9;
    add r9 r6 into r10;
    set r10 into account[r5];


function transfer_private:
    input r0 as address.private;
    input r1 as u64.private;
    input r2 as u64.public;
    assert.eq r2 2u64;
    add r1 r2 into r3;
    call helper.aleo/mint_private self.caller r3 into r4;
    call helper.aleo/verify_balance self.caller into r5;
    call helper.aleo/transfer_relayer_private 1u64 r4 into r6 r7;
    call fees.aleo/fees 1u64 into r8;
    sub r7.amount r1 into r9;
    sub r9 1u64 into r10;
    cast r7.owner r10 into r11 as balance.record;
    cast r0 r1 into r12 as balance.record;
    async transfer_private r5 r8 into r13;
    output r11 as balance.record;
    output r12 as balance.record;
    output r13 as multi_txn_t1.aleo/transfer_private.future;

finalize transfer_private:
    input r0 as helper.aleo/verify_balance.future;
    input r1 as fees.aleo/fees.future;
    await r0;
    await r1;
