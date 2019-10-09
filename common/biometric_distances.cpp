/**
 \file 		biometric_distances.cpp
 \author 	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementation of biometric distances/scores + help functions on circuits using ABY Framework.
 */

#include "biometric_distances.h"

int HammingDist(long int x, long int y) {
    int dist = 0;
	uint64_t val = x^y;
	while(val) {
		++dist; 
		val &= val - 1;
	}
	return dist;
}

long int TwoCovDist(std::vector<long int> &x, std::vector<long int> &y, std::vector<std::vector<long int>> &L, std::vector<std::vector<long int>> &G,
        std::vector<long int > &c, long int k, uint32_t num) {
    long int res = k;

    //x^T * L * y
    std::vector<long int > Ly = DotProd(L, y, num);
    res += VecProd(x, Ly, num);

    //y^T * L * x
    std::vector<long int > Lx = DotProd(L, x, num);
    res += VecProd(y, Lx, num);

    //x^T * G * x
    std::vector<long int > Gx = DotProd(G, x, num);
    res += VecProd(x, Gx, num);

    //y^T * G * y
    std::vector<long int > Gy = DotProd(G, y, num);
    res += VecProd(y, Gy, num);

    //c^T * (x + y)
    std::vector<long int > xy = VecAdd(x, y, num);
    res += VecProd(c, xy, num);

    return res;
}

double TwoCovDist(std::vector<double> &x, std::vector<double> &y, std::vector<std::vector<double>> &L, std::vector<std::vector<double>> &G,
                    std::vector<double> &c, double k, uint32_t num) {
    double res = k;

    //x^T * L * y
    std::vector<double > Ly = DotProd(L, y, num);
    res += VecProd(x, Ly, num);

    //y^T * L * x
    std::vector<double > Lx = DotProd(L, x, num);
    res += VecProd(y, Lx, num);

    //x^T * G * x
    std::vector<double > Gx = DotProd(G, x, num);
    res += VecProd(x, Gx, num);

    //y^T * G * y
    std::vector<double> Gy = DotProd(G, y, num);
    res += VecProd(y, Gy, num);

    //c^T * (x + y)
    std::vector<double> xy = VecAdd(x, y, num);
    res += VecProd(c, xy, num);

    return res;
}

long int PLDADist(std::vector<long int > & x, std::vector<long int > & y, std::vector<std::vector<long int>> & Q, std::vector<std::vector<long int>> & P, long int k, uint32_t num) {
    long int res = k;

    //x^t * Q * x
    std::vector<long int > Qx = DotProd(Q, x, num);
    res += VecProd(x, Qx, num);

    //y^t * Q * y
    std::vector<long int > Qy = DotProd(Q, y, num);
    res += VecProd(y, Qy, num);

    //2*x^t * P * y
    std::vector<long int > Py = DotProd(P, y, num);
    res += 2*VecProd(x, Py, num);

    return res;
}

double PLDADist(std::vector<double > & x, std::vector<double> & y, std::vector<std::vector<double>> & Q, std::vector<std::vector<double>> & P, double k, uint32_t num) {
    double res = k;

    //x^t * Q * x
    std::vector<double > Qx = DotProd(Q, x, num);
    res += VecProd(x, Qx, num);

    //y^t * Q * y
    std::vector<double > Qy = DotProd(Q, y, num);
    res += VecProd(y, Qy, num);

    //2*x^t * P * y
    std::vector<double > Py = DotProd(P, y, num);
    res += 2*VecProd(x, Py, num);

    return res;
}

std::vector<long int > VecAdd(std::vector<long int > & x, std::vector<long int > & y, uint32_t num) {
    std::vector<long int > res;
    for (int i = 0; i < num; ++i) {
        res.push_back(x.at(i) + y.at(i));
    }

    return res;
}

std::vector<double > VecAdd(std::vector<double > & x, std::vector<double > & y, uint32_t num) {
    std::vector<double >  res;
    for (int i = 0; i < num; ++i) {
        res.push_back(x.at(i) + y.at(i));
    }

    return res;
}

long int VecProd(std::vector<long int >& x, std::vector<long int >& y, uint32_t num) {
    long int res = 0;
    for (int i = 0; i < num; ++i) {
        res += x.at(i) * y.at(i);
    }
    return res;
}

double VecProd(std::vector<double> &x, std::vector<double> &y, uint32_t num) {
    double res = 0;
    for (int i = 0; i < num; ++i) {
        res += x.at(i) * y.at(i);
    }
    return res;
}

std::vector<long int> DotProd(std::vector<std::vector<long int >> &  M, std::vector<long int > &v, uint32_t num) {
    uint32_t i, j;
    std::vector<long int > res;
    for (i = 0; i < num; ++i) {
        long int prod = 0;
        for (j = 0; j < num; ++j) {
            prod += M.at(i).at(j) * v.at(j);
        }
        res.push_back(prod);
    }
    return res;
}

std::vector<double> DotProd(std::vector<std::vector<double >> &  M, std::vector<double> & v, double num) {
    uint32_t i, j;
    std::vector<double> res;
    for (i = 0; i < num; ++i) {
        double prod = 0.0;
        for (j = 0; j < num; ++j) {
            prod += M.at(i).at(j) * v.at(j);
        }
        res.push_back(prod);
    }
    return res;
}

share_p BuildHammingCircuit(share_p s_x, share_p s_y, uint32_t num, CircuitW_p bc) {

	s_x = bc->PutXORGate(s_x, s_y);

	s_x = bc->PutHammingWeightGate(s_x);

	s_x = putSumGate(s_x, num, bc);

	return s_x;
}


share_p BuildCosineCircuit(share_p s_x, share_p s_y, uint32_t num, CircuitW_p ac) {
	// pairwise multiplication of all input values
	share_p s_prod = ac->PutMULGate(s_x, s_y);

	share_p s_res = putSumGate(s_prod, num, ac);

    return s_res;
}

share_p BuildEuclideanCircuit(share_p s_x, share_p s_y, uint32_t num, CircuitW_p ac) {
    uint64_t two = 2;
    share_p s_two = ac->PutCONSGate(two, s_x->get_bitlength());
    s_two = ac->PutRepeaterGate(num, s_two);
    share_p s_x2 = ac->PutMULGate(s_x, s_x);
    share_p s_y2 = ac->PutMULGate(s_y, s_y);
    share_p s_adds = ac->PutADDGate(s_x2, s_y2);
    share_p s_sub = ac->PutSUBGate(s_adds, ac->PutMULGate(s_two, ac->PutMULGate(s_x, s_y)));

    share_p s_res = putSumGate(s_sub, num, ac);

	return s_res;
}

share_p BuildThresholdCircuit(share_p s_dist, uint64_t t, uint32_t bitlen, CircuitW_p bc) {
    //Compute two-complement GT Function
	share_p s_t = bc->PutCONSGate(t,bitlen);
	share_p s_gt = bc->PutGTGate(s_t, s_dist);

	//optimized (only 1 AND:) output functionality is equivalent to (~(aXb)&(aXc))Xb
    share_p s_msba = share_p(s_t.get()->get_wire_ids_as_share(bitlen-1));
    share_p s_msbb = share_p(s_dist.get()->get_wire_ids_as_share(bitlen-1));

    share_p s_axb = bc->PutXORGate(s_msba,s_msbb);
    share_p s_naxb = bc->PutBINVGate(s_axb);

    share_p s_axc = bc->PutXORGate(s_msba,s_gt);

    share_p s_res = bc->PutANDGate(s_naxb, s_axc);

    s_res = bc->PutXORGate(s_res, s_msbb);

    /* //unoptimized:
    share_p s_na = bc->PutBINVGate(s_msba);

    share_p s_nac = bc->PutANDGate(s_na, s_gt);

    share_p s_nab = bc->PutANDGate(s_na, s_msbb);

    share_p s_bc = bc->PutANDGate(s_msbb, s_gt);

    share_p s_res = bc->PutORGate(s_nac, s_nab);

    s_res = bc->PutORGate(s_res, s_bc);*/

	return s_res;
}

share_p BuildTwoCovCircuit(share_p s_x, share_p s_y, std::vector<share_p> s_L, std::vector<share_p> s_G, share_p s_c, share_p s_k, uint32_t num, CircuitW_p ac) {

    //x^T * L * y + k
    share_p s_vres = putDotGate(s_L, s_y, num, ac);
    s_vres = ac->PutMULGate(s_x, s_vres);
    share_p s_res = ac->PutADDGate(s_k, putSumGate(s_vres, num, ac));


    //y^T * L * x
    s_vres = putDotGate(s_L, s_x, num, ac);
    s_vres = ac->PutMULGate(s_y, s_vres);
    s_res = ac->PutADDGate(s_res, putSumGate(s_vres, num, ac));

    //x^T * G * x
    s_vres = putDotGate(s_G, s_x, num, ac);
    s_vres = ac->PutMULGate(s_x, s_vres);
    s_res = ac->PutADDGate(s_res, putSumGate(s_vres, num, ac));

    //y^T * G * y
    s_vres = putDotGate(s_G, s_y, num, ac);
    s_vres = ac->PutMULGate(s_y, s_vres);
    s_res = ac->PutADDGate(s_res, putSumGate(s_vres, num, ac));

    //c^T * (x + y)
    s_vres = ac->PutADDGate(s_x, s_y);
    s_vres = ac->PutMULGate(s_c, s_vres);
    s_res = ac->PutADDGate(s_res, putSumGate(s_vres, num, ac));
 
    return s_res;

}

share_p BuildPLDACircuit(share_p s_x, share_p s_y, std::vector<share_p> s_Q, std::vector<share_p> s_P, share_p s_k, uint32_t num, CircuitW_p ac) {
    //x^T * Q * x + k
    share_p s_Qx = putDotGate(s_Q, s_x, num, ac);
    share_p s_xQx = ac->PutMULGate(s_x, s_Qx);
    share_p s_1 = ac->PutADDGate(s_k, putSumGate(s_xQx, num, ac));

    //y^T * Q * y
    share_p s_Qy = putDotGate(s_Q, s_y, num, ac);
    share_p s_yQy = ac->PutMULGate(s_y, s_Qy);
    share_p s_2 = ac->PutADDGate(s_1, putSumGate(s_yQy, num, ac));

    //2* x^T * P * y
    share_p s_Py = putDotGate(s_P, s_y, num, ac);
    share_p s_xPy = ac->PutMULGate(s_x, s_Py);
    share_p s_xPysum = putSumGate(s_xPy, num, ac);
    share_p s_3 = ac->PutADDGate(s_2, s_xPysum);
    share_p s_res = ac->PutADDGate(s_3, s_xPysum);

    return s_res;
}



share_p putDotGate(std::vector<share_p> s_m, share_p s_v, uint32_t num, CircuitW_p ac) {
    uint32_t i;
    std::vector<share_p> s_res;

    for (i = 0; i < num; ++i) {
        share_p s_tmp = ac->PutMULGate(s_m.at(i), s_v);
        s_res.push_back(putSumGate(s_tmp, num, ac));
    }
    return toSIMD(s_res, num, ac);
}

share_p putSumGate(share_p s_simd, uint32_t num, CircuitW_p ac) {
    uint32_t posNil[] = {0};

    share_p s_res = ac->PutSubsetGate(s_simd, posNil,1);

    for (uint32_t i = 1; i < num; ++i) {
        uint32_t pos[] = {i};
        share_p s_tmp = ac->PutSubsetGate(s_simd, pos, 1);
        s_res = ac->PutADDGate(s_res, s_tmp);
    }

    return s_res;
}

share_p putFPDotGate(std::vector<share_p> s_m, share_p s_v, uint32_t num, uint32_t bitlen, CircuitW_p ac) {
    uint32_t i;
    std::vector<share_p> s_res;

    for (i = 0; i < num; ++i) {
        share_p s_tmp = ac->PutFPGate(s_m.at(i), s_v, MUL, bitlen, num, no_status);
        s_res.push_back(putFPSumGate(s_tmp, num, bitlen, ac));
    }
    return toSIMD(s_res, num, ac, S_BOOL);
}

share_p BuildFPCosineCircuit(share_p s_x, share_p s_y, uint32_t num, uint32_t bitlen, CircuitW_p bc) {

	s_x = bc->PutFPGate(s_x, s_y, MUL, bitlen, num, no_status);

	s_x = putFPSumGate(s_x, num, bitlen, bc);

	return s_x;
}

share_p BuildFPEuclideanCircuit(share_p s_x, share_p s_y, uint32_t num, uint32_t bitlen, CircuitW_p ac) {
	share_p s_res;
	
	double two = 2.0;

    uint64_t* twoptr = (uint64_t*) &two;
    share_p s_two = ac->PutCONSGate(*twoptr, s_x->get_bitlength());
    s_two = ac->PutRepeaterGate(num, s_two);
    share_p s_x2 = ac->PutFPGate(s_x, s_x, MUL, bitlen, num, no_status);
    share_p s_y2 = ac->PutFPGate(s_y, s_y, MUL, bitlen, num, no_status);
    s_res = ac->PutFPGate(s_x2, s_y2, ADD, bitlen, num, no_status);
    s_res = ac->PutFPGate(s_res, ac->PutFPGate(s_two, ac->PutFPGate(s_x, s_y, MUL, bitlen, num, no_status), MUL, bitlen, num, no_status), SUB, bitlen, num, no_status);

    s_res = putFPSumGate(s_res, num,  bitlen, ac);

	return s_res;
}

share_p BuildFPTwoCovCircuit(share_p s_x, share_p s_y, std::vector<share_p> s_L, std::vector<share_p>s_G, share_p s_c, share_p s_k, uint32_t num, uint32_t bitlen, CircuitW_p ac) {

    //x^T * L * y + k
    share_p s_vres = putFPDotGate(s_L, s_y, num, bitlen, ac);
    s_vres = ac->PutFPGate(s_x, s_vres, MUL, bitlen, num, no_status);
    share_p s_res = ac->PutFPGate(s_k, putFPSumGate(s_vres, num, bitlen, ac), ADD, bitlen, 1, no_status);


    //y^T * L * x
    s_vres = putFPDotGate(s_L, s_x, num, bitlen, ac);
    s_vres = ac->PutFPGate(s_y, s_vres, MUL, bitlen, num, no_status);
    s_res = ac->PutFPGate(s_res, putFPSumGate(s_vres, num, bitlen, ac), ADD, bitlen, 1, no_status);



    //x^T * G * x
    s_vres = putFPDotGate(s_G, s_x, num, bitlen, ac);
    s_vres = ac->PutFPGate(s_x, s_vres, MUL, bitlen, num, no_status);
    s_res = ac->PutFPGate(s_res, putFPSumGate(s_vres, num, bitlen, ac), ADD, bitlen, 1, no_status);


    //y^T * G * y
    s_vres = putFPDotGate(s_G, s_y, num, bitlen, ac);
    s_vres = ac->PutFPGate(s_y, s_vres, MUL, bitlen, num, no_status);
    s_res = ac->PutFPGate(s_res, putFPSumGate(s_vres, num, bitlen, ac), ADD, bitlen, 1, no_status);


    //c^T * (x + y)
    s_vres = ac->PutFPGate(s_x, s_y, ADD, bitlen, num, no_status);
    s_vres = ac->PutFPGate(s_c, s_vres, MUL, bitlen, num, no_status);
    s_res = ac->PutFPGate(s_res, putFPSumGate(s_vres, num, bitlen, ac), ADD, bitlen, 1, no_status);

    return s_res;
}

share_p BuildFPPLDACircuit(share_p s_x, share_p s_y, std::vector<share_p> s_Q, std::vector<share_p> s_P, share_p s_k, uint32_t num, uint32_t bitlen, CircuitW_p ac) {
    //x^T * Q * x + k
    share_p s_Qx = putFPDotGate(s_Q, s_x, num, bitlen, ac);
    share_p s_xQx = ac->PutFPGate(s_x, s_Qx, MUL, bitlen, num, no_status);
    share_p s_1 = ac->PutFPGate(s_k, putFPSumGate(s_xQx, num, bitlen, ac), ADD, bitlen, 1, no_status);

    //y^T * Q * y
    share_p s_Qy = putFPDotGate(s_Q, s_y, num, bitlen, ac);
    share_p s_yQy = ac->PutFPGate(s_y, s_Qy, MUL, bitlen, num, no_status);
    share_p s_2 = ac->PutFPGate(s_1, putFPSumGate(s_yQy, num, bitlen, ac), ADD, bitlen, 1, no_status);

    //2* x^T * P * y
    share_p s_Py = putFPDotGate(s_P, s_y, num, bitlen, ac);

    share_p s_xPy = ac->PutFPGate(s_x, s_Py, MUL, bitlen, num, no_status);
    share_p s_xPysum = putFPSumGate(s_xPy, num, bitlen, ac);
    share_p s_3 = ac->PutFPGate(s_2, s_xPysum, ADD, bitlen, 1, no_status);
    share_p s_res = ac->PutFPGate(s_3, s_xPysum, ADD, bitlen, 1, no_status);

    return s_res;
}

share_p BuildFPThresholdCircuit(share_p s_dist, uint64_t t, uint32_t bitlen, CircuitW_p bc) {
    share_p s_t = bc->PutCONSGate(t, bitlen);
    return bc->PutFPGate(s_t, s_dist, CMP, bitlen, 1, no_status);
}

share_p putFPSumGate(share_p s_simd, uint32_t num, uint32_t bitlen, CircuitW_p bc) {
    std::vector<share_p> s(num);
    share_p s_res;
    for (uint32_t i = 0; i < num; ++i) {
        uint32_t pos[] = {i};
        s_res = i == 0 ? bc->PutSubsetGate(s_simd, pos, 1) :
                bc->PutFPGate(s_res, bc->PutSubsetGate(s_simd, pos, 1), ADD, bitlen, 1, no_status);
    }
    return s_res;
}

share_p toSIMD(std::vector<share_p> s, uint32_t num, CircuitW_p ac, e_sharing sharing) {
    uint32_t i,j;

    uint32_t len = (s[0])->get_bitlength();

    std::vector<std::vector<uint32_t> > res(len);
    std::vector<uint32_t> v;

    for (i = 0; i < num; ++i)  {
        for (j = 0; j < len; ++j) {
            res.at(j).push_back(s.at(i)->get_wires().at(j));
        }
    }

    for (j = 0; j < len; ++j) {
        v.push_back(ac->PutCombinerGate(res.at(j)));
    }

    share_p s_res;

    switch(sharing) {
        case S_BOOL :
            s_res = std::make_shared<boolshare>(v, ac->circ_);
            break;
        case S_ARITH:
            s_res = std::make_shared<arithshare>(v, ac->circ_);
            break;
    }

    return s_res;
}
