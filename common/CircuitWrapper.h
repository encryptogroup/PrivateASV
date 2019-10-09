//
// Created by amos on 24.09.18. Thanks to Lennart Braun for some code.
//

#ifndef PROJECT_CIRCUITWRAPPER_H
#define PROJECT_CIRCUITWRAPPER_H

#include <abycore/circuit/arithmeticcircuits.h>
#include "../../../abycore/sharing/sharing.h"
#include <memory>
#include <numeric>
#include <abycore/circuit/booleancircuits.h>

using share_p = std::shared_ptr<share>;

class CircuitWrapper {

public:
    CircuitWrapper(Circuit *circ) : circ_(circ) {}

    share_p PutSharedSIMDINGate(uint32_t num, uint64_t* invals, uint32_t bitlen) {
        return share_p (circ_->PutSharedSIMDINGate(num, invals, bitlen));
    }

    share_p PutOUTGate(share_p ina, e_role role)
    {
        return share_p(circ_->PutOUTGate(ina.get(), role));
    }

    share_p PutSharedINGate(uint64_t val, uint32_t bitlen)
    {
        return share_p(circ_->PutSharedINGate(val, bitlen));
    }

    share_p PutFPGate(share_p ina, share_p inb, op_t op, uint8_t bitlen, uint32_t nvals, fp_op_setting s) {

        return share_p(((BooleanCircuit*)circ_)->PutFPGate(ina.get(), inb.get(), op, bitlen, nvals, s));
    }


    share_p PutSharedOUTGate(share_p ina)
    {
        return share_p(circ_->PutSharedOUTGate(ina.get()));
    }

    template <typename T,
            typename = std::enable_if_t<std::is_unsigned<T>::value>>
    share_p PutCONSGate(T input, size_t size)
    {
        assert(size <= sizeof(input) * 8);
        assert(size <= std::numeric_limits<uint32_t>::max());
        return share_p(circ_->PutCONSGate(input, static_cast<uint64_t>(size)));
    }


    share_p PutGTGate(share_p ina, share_p inb)
    {
        return share_p(circ_->PutGTGate(ina.get(), inb.get()));
    }

    share_p PutADDGate(share_p ina, share_p inb)
    {
        return share_p(circ_->PutADDGate(ina.get(), inb.get()));
    }

    share_p PutSUBGate(share_p ina, share_p inb)
    {
        return share_p(circ_->PutSUBGate(ina.get(), inb.get()));
    }

    share_p PutXORGate(share_p ina, share_p inb)
    {
        return share_p(circ_->PutXORGate(ina.get(), inb.get()));
    }

    share_p PutMULGate(share_p ina, share_p inb)
    {
        return share_p(circ_->PutMULGate(ina.get(), inb.get()));
    }

    share_p PutANDGate(share_p ina, share_p inb) {
        return share_p(circ_->PutANDGate(ina.get(), inb.get()));
    }

    share_p PutORGate(share_p ina, share_p inb) {
        return share_p(((BooleanCircuit*)circ_)->PutORGate(ina.get(), inb.get()));
    }

    share_p PutHammingWeightGate(share_p in) {
        return share_p(((BooleanCircuit*)circ_)->PutHammingWeightGate(in.get()));
    }

    share_p PutBINVGate(share_p in) {
        return share_p(((BooleanCircuit*)circ_)->PutINVGate(in.get()));
    }

    share_p PutSubsetGate(share_p in, uint32_t* pos, uint32_t nvals_out) {
        return share_p(circ_->PutSubsetGate(in.get(), pos, nvals_out));
    }

    uint32_t PutCombinerGate(std::vector<uint32_t> input) {
        return circ_->PutCombinerGate(input);
    }

    share_p PutRepeaterGate(uint32_t nvals, share_p in) {
        return share_p(circ_->PutRepeaterGate(nvals, in.get()));
    }

    share_p PutA2YGate(share_p in) {
        return share_p(circ_->PutA2YGate(in.get()));
    }

    share_p PutB2YGate(share_p in) {
        return share_p(circ_->PutB2YGate(in.get()));
    }

    // debug gates
    share_p PutPrintValueGate(share_p in, std::string infostring)
    {
        return share_p(circ_->PutPrintValueGate(in.get(), infostring));
    }

    template <typename T,
            typename = std::enable_if_t<std::is_unsigned<T>::value>>
    share_p PutAssertGate(share_p in, T value, size_t size)
    {
        return share_p(circ_->PutAssertGate(in, value, size));
    }


    static share_p get_wire_ids_as_share(share_p share, size_t index)
    {
        assert(index <= std::numeric_limits<uint32_t>::max());
        return share_p(share->get_wire_ids_as_share(static_cast<uint32_t>(index)));
    }

// private:
    Circuit* circ_;

};

using CircuitW_p = std::shared_ptr<CircuitWrapper>;

#endif //PROJECT_CIRCUITWRAPPER_H
