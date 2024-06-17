program fees.aleo;

record balance:
    owner as address.private;
    amount as u64.private;


mapping account:
	key as address.public;
	value as u64.public;

function fees:
    input r0 as u64.public;
    assert.neq r0 0u64;
    async fees self.caller r0 into r1;
    output r1 as fees.aleo/fees.future;

finalize fees:
    input r0 as address.public;
    input r1 as u64.public;
    get.or_use account[r0] 0u64 into r2;
    sub r2 r1 into r3;
    set r3 into account[r0];


function fees_private:
    input r0 as balance.record;
    input r1 as u64.public;
    assert.neq r1 0u64;
    sub r0.amount r1 into r2;
    cast r0.owner r2 into r3 as balance.record;
    output r3 as balance.record;
