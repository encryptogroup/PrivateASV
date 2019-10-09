/**
 \file 		biometric.cpp
 \author 	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementation of biometric distance/score threshold verification using ABY Framework.
 */
#include "biometric.h"
#include "biometric_distances.h"


std::vector<uint64_t > inttouint(std::vector<long int> in) {
    std::vector<uint64_t > res;
    for (long int i : in) {
        res.push_back(static_cast<uint64_t >(i));
    }
    return res;
}

std::vector<long int> dtouint(std::vector<double> in) {
    std::vector<long int> res;
    for (double f : in) {
        res.push_back(* (uint64_t*) &f);
    }
    return res;
}

Biometric::Biometric(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, 
	uint32_t num, e_sharing sharing, uint16_t dist_type, uint16_t use_float, uint32_t iter, uint16_t mode, long int thresh, std::string comparisons_file, uint32_t subspace) {
		this->errors = 0;
		this->online_time=0.0;
		this->total_time=0.0;
		this->online_bytes_sent=0, this->total_bytes_sent=0;
		this->online_bytes_recv=0, this->total_bytes_recv=0;
		this->t = thresh;
		this->td = (double) thresh / 100000;
		this->mode = mode;
		this->role = role;
		this->num = num;
		this->iter = iter;
		this->bitlen = bitlen;
		this->subspace = subspace;
		this->comparisons_file = comparisons_file;
		this->use_float = use_float;
		if (use_float && dist_type == HAMMING) 	{
			/* HAMMING can only be computed using int */
			this->use_float = USE_INT;
		}
		this->dist_type = dist_type;
		this->sharing = sharing;

		for (int i = 0; i < num; ++i) {
			this->dummyvals.push_back(0);
		}

		this->party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);

		if (this->mode != MODE_RNG && this->role == SERVER) { //read data from provided files
            this->bioReader.setNum(num);
            this->bioReader.setUseFloat(use_float);
            this->bioReader.readComparisons(this->comparisons_file);
            this->bioReader.readReferences("references" + std::to_string(this->num));
            this->bioReader.readProbes("probes" + std::to_string(this->num));
            if (this->dist_type == TWOCOV) {
                this->bioReader.read2CovModel("k" + std::to_string(this->num),
                                          "c" + std::to_string(this->num),
                                          "L" + std::to_string(this->num),
                                          "G" + std::to_string(this->num));
            } else if (this->dist_type == PLDA) {
                this->bioReader.readPLDAModel("PLDA_k" + std::to_string(this->num) + "_" + std::to_string(subspace),
                                          "PLDA_Q" + std::to_string(this->num) + "_" + std::to_string(subspace),
                                          "PLDA_P" + std::to_string(this->num) + "_" + std::to_string(subspace));
            }
        }

}

void Biometric::computePlain() {

    if (this->use_float) {
        switch(this->dist_type) {
            case TWOCOV: {
                this->v_sumd = TwoCovDist(this->xvalsF, this->yvalsF, this->LF, this->GF, this->cF, this->kF, this->num);
                break;
            }
            case PLDA: {
                this->v_sumd = PLDADist(this->xvalsF, this->yvalsF, this->LF, this->GF, this->kF, this->num);
                break;
            }
        }

    } else {

        switch(this->dist_type) {
            case TWOCOV: {
                this->v_sum = TwoCovDist(this->xvals, this->yvals, this->L, this->G, this->c, this->k, this->num);
                break;
            }
            case PLDA: {
                this->v_sum = PLDADist(this->xvals, this->yvals, this->L, this->G, this->k, this->num);
                break;
            }

        }

    }


}

void Biometric::generateRandomInputs() {
	srand(time(NULL));
	uint32_t i;
	double xd=0.0, yd=0.0;
	long int x=0, y=0;
	
	this-> v_sumd = 0.0;
	this-> v_sum = 0;

	if (this->use_float) {

		for (i = 0; i < this->num; ++i) {
			xd = ((float) rand()) / (float) RAND_MAX;
			yd = ((float) rand()) / (float) RAND_MAX;

			this->xvalsF.push_back(xd);
			this->yvalsF.push_back(yd);

			switch (this->dist_type) {
				case EUCLIDEAN :
					this->v_sumd += xd * xd + yd * yd - 2 * xd * yd;
					break;
				case COSINE :
					this->v_sumd += xd * yd;
					break;
				case TWOCOV : {
					std::vector<double> LFvec, GFvec;
					std::vector<long int> Lvec, Gvec;
					for (int j = 0; j < num; ++j) {
						double f0 = ((float) rand()) / (float) RAND_MAX;
						double f1 = ((float) rand()) / (float) RAND_MAX;
						LFvec.push_back(f0);
						Lvec.push_back(*(uint64_t *) &f0);
						GFvec.push_back(f1);
						Gvec.push_back(*(uint64_t *) &f1);
					}
					this->LF.push_back(LFvec);
					this->L.push_back(Lvec);
					this->GF.push_back(GFvec);
					this->G.push_back(Gvec);
					double f2 = ((float) rand()) / (float) RAND_MAX;
					this->cF.push_back(f2);
					this->c.push_back(*(uint64_t *) &f2);
					break;
				}
				case PLDA : {
					std::vector<double> LFvec, GFvec;
					std::vector<long int> Lvec, Gvec;
					for (int j = 0; j < num; ++j) {
						double f0 = ((float) rand()) / (float) RAND_MAX;
						double f1 = ((float) rand()) / (float) RAND_MAX;
						LFvec.push_back(f0);
						Lvec.push_back(*(uint64_t *) &f0);
						GFvec.push_back(f1);
						Gvec.push_back(*(uint64_t *) &f1);
					}
					this->LF.push_back(LFvec);
					this->L.push_back(Lvec);
					this->GF.push_back(GFvec);
					this->G.push_back(Gvec);
					break;
				}
			}

			uint64_t *xptr = (uint64_t *) &xd;
			uint64_t *yptr = (uint64_t *) &yd;

			this->xvals.push_back(*xptr);
			this->yvals.push_back(*yptr);

		}

		if (this->dist_type == TWOCOV || this->dist_type == PLDA) {
			this->kF = ((float) rand()) / (float) RAND_MAX;
			this->k = *(uint64_t * ) & this->kF;
		}

		if (rand() % 2)
			this->td = this->v_sumd - 1;
		else
			this->td = this->v_sumd + 1;

	} else {
		for (i = 0; i < this->num; ++i) {
			x = -(rand() % 1000);
			y = rand() % 1000;

			switch (dist_type) {
				case EUCLIDEAN :
					this->v_sum += x * x + y * y - 2 * x * y;
					break;
				case COSINE :
					this->v_sum += x * y;
					break;
				case HAMMING :
					this->v_sum += HammingDist(x, y);
					break;
				case TWOCOV : {
					std::vector<long int> Lvec;
					std::vector<long int> Gvec;
					for (int j = 0; j < this->num; ++j) {
						Lvec.push_back(rand());
						Gvec.push_back(rand());
					}
					this->L.push_back(Lvec);
					this->G.push_back(Gvec);
					this->c.push_back(rand());
					break;
				}
				case PLDA : {
					std::vector<long int> LvecP;
					std::vector<long int> GvecP;
					for (int j = 0; j < this->num; ++j) {
						LvecP.push_back(rand());
						GvecP.push_back(rand());
					}
					this->L.push_back(LvecP);
					this->G.push_back(GvecP);
					break;
				}
			}

			this->xvals.push_back(x);
			this->yvals.push_back(y);

		}

		if (this->dist_type == TWOCOV || this->dist_type == PLDA)
			this->k = rand();

		if (rand() % 2)
			this->t = this->v_sum - 1;
		else
			this->t = this->v_sum + 1;

	}

	this->computePlain();
}

void Biometric::getInputsFromBioReader(std::string spID, std::string prID) {
	srand(time(NULL));
	uint32_t i;
	double xF=0.0, yF=0.0;
	long int x=0, y=0;

	this-> v_sumd = 0.0;
	this-> v_sum = 0;

	std::vector<long int> yvec, xvec;
	std::vector<double> yvecF, xvecF;

	if (this->use_float) {

		yvecF = this->bioReader.getReferenceF(spID);
		xvecF = this->bioReader.getProbeF(prID);

		for (i = 0; i < this->num; ++i) {
			xF = xvecF.at(i);
			xvec.push_back(*(uint64_t *) &xF);
			yF = yvecF.at(i);
			yvec.push_back(*(uint64_t *) &yF);
			switch (dist_type) {
				case EUCLIDEAN :
					this->v_sumd += xF * xF + yF * yF - 2 * xF * yF;
					break;
				case COSINE :
					this->v_sumd += xF * yF;
					break;
				default : //PLDA or TWOCOV
					this->LF.push_back(this->bioReader.getLLineF(i));
					this->L.push_back(dtouint(this->LF.at(i)));
					this->GF.push_back(this->bioReader.getGLineF(i));
					this->G.push_back(dtouint(this->GF.at(i)));
					break;
			}
		}

		if (this->dist_type == TWOCOV) {
			this->cF = this->bioReader.getCF();
			for (auto f : cF) {
				this->c.push_back(*(uint64_t *) &f);
			}
		}
		if (this->dist_type == TWOCOV || this->dist_type == PLDA) {
			this->kF = this->bioReader.getKF();
			this->k = *(uint64_t *) &this->kF;
		}

	} else {

		yvec = this->bioReader.getReference(spID);
		xvec = this->bioReader.getProbe(prID);

		for (i = 0; i < this->num; ++i) {
			x = xvec.at(i);
			y = yvec.at(i);
			switch(dist_type) {
				case EUCLIDEAN : 
					this->v_sum += x*x + y*y - 2*x*y;
					break;
				case COSINE : 
					this->v_sum += x*y;
					break;
				case HAMMING :
					this->v_sum += HammingDist(x,y);
					break;
                default : //PLDA or TWOCOV
					this->L.push_back(this->bioReader.getLLine(i));
					this->G.push_back(this->bioReader.getGLine(i));
					break;
			}
		}

		if (this->dist_type == TWOCOV)
			this->c = this->bioReader.getC();
		if (this->dist_type == TWOCOV || this->dist_type == PLDA)
			this->k = this->bioReader.getK();


	}
	this->xvals = xvec;
	this->xvalsF = xvecF;
	this->yvals = yvec;
    this->yvalsF = yvecF;

	this->computePlain();

}


void Biometric::initiateCircuits() {
	std::vector<Sharing*>& sharings = this->party->GetSharings();

	ArithmeticCircuit* ac =	(ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();
	BooleanCircuit* yc = (BooleanCircuit*) sharings[S_YAO]->GetCircuitBuildRoutine();
	BooleanCircuit* bc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	if (this->use_float || this->dist_type == HAMMING) //We have to use BOOL sharing in that case
	    this->ac = std::make_shared<CircuitWrapper>(bc);
	else //Use scaled ARITH solution
	    this->ac = std::make_shared<CircuitWrapper>(ac);
	this->yc = std::make_shared<CircuitWrapper>(yc);
}


void Biometric::inputB2Y() {
    this->s_x = this->yc->PutB2YGate(this->s_x);
    this->s_y = this->yc->PutB2YGate(this->s_y);
    if (this->dist_type == TWOCOV)
        this->s_c = this->yc->PutB2YGate(this->s_c);
    if (this->dist_type == PLDA || this->dist_type == TWOCOV) {
        this->s_k = this->yc->PutB2YGate(this->s_k);
        for (int j = 0; j < this->num; ++j)	{
            this->s_L[j] =  this->yc->PutB2YGate(this->s_L[j]);
            this->s_G[j] =  this->yc->PutB2YGate(this->s_G[j]);
        }
    }
}

void Biometric::preSharePLDA() {

	switch(this->role) {
		case SERVER :
			this->s_x = this->ac->PutSharedSIMDINGate(this->num, inttouint(this->xvals).data(), this->bitlen);
			this->s_y = this->ac->PutSharedSIMDINGate(this->num, inttouint(this->yvals).data(), this->bitlen);
			if (this->dist_type == TWOCOV)
				this->s_c = this->ac->PutSharedSIMDINGate(this->num, inttouint(this->c).data(), this->bitlen);
			this->s_k = this->ac->PutSharedINGate(static_cast<uint64_t >(this->k), this->bitlen);
			for (int j = 0; j < this->num; ++j)	{
				this->s_L.push_back(this->ac->PutSharedSIMDINGate(this->num, inttouint(this->L.at(j)).data(), this->bitlen));
				this->s_G.push_back(this->ac->PutSharedSIMDINGate(this->num, inttouint(this->G.at(j)).data(), this->bitlen));
			}
			break;
		case CLIENT :
			this->s_x = this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen);
			this->s_y = this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen);
            if (this->dist_type == TWOCOV)
			    this->s_c = this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen);
			uint64_t nil = 0;
			this->s_k = this->ac->PutSharedINGate(nil, this->bitlen);
			for (int j = 0; j < this->num; ++j)	{
				this->s_L.push_back(this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen));
				this->s_G.push_back(this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen));
			}
			break;
	}
}

void Biometric::preShareInputs() {
	/*
	Pre-Share inputs: Here we use x1 = x and x2 = 0 (=dummyvals) as secret sharing.
	*/

	if (this->dist_type == PLDA || this->dist_type == TWOCOV) {
		this->preSharePLDA();
	}  else {
		//=> use Arith Pre-Sharing
		switch(this->role) {
			case SERVER : 
				this->s_x = this->ac->PutSharedSIMDINGate(this->num, inttouint(this->xvals).data(), this->bitlen);
				this->s_y = this->ac->PutSharedSIMDINGate(this->num, inttouint(this->yvals).data(), this->bitlen);
				break;
			case CLIENT :
				this->s_x = this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen);
				this->s_y = this->ac->PutSharedSIMDINGate(this->num, this->dummyvals.data(), this->bitlen);
				break;
		}
	}

	//want to try yao instead (only 1 round of communication)
    if (this->use_float && this->sharing == S_YAO)
        this->inputB2Y();
}

void Biometric::logResults() {
    if (this->mode == MODE_ULINK)	{
        /* we need to log score share Z1/Z2 => use additional SHARED SIMD out gate to obtain shares of Z */
        this->s_score = this->ac->PutSharedOUTGate(this->s_out);
    } else if (this->mode == MODE_BIOPER) {
        /* we need to log score => use additional out gate to obtain plaintext */
        this->s_score = this->ac->PutOUTGate(this->s_out, ALL);
    }
}

void Biometric::buildCircuits() {
	/*
		Build Score & Threshold Circuits
	*/

	if (this->use_float) {
		//FLOAT inputs: use either BOOL or YAO for circuits

		CircuitW_p circ;
		this->sharing == S_YAO ? circ = this->yc : circ = this->ac;

        switch(this->dist_type) {
            case EUCLIDEAN :
                this->s_out = BuildFPEuclideanCircuit(this->s_x, this->s_y, this->num, this->bitlen, circ);
                break;
            case COSINE :
                this->s_out = BuildFPCosineCircuit(this->s_x, this->s_y, this->num, this->bitlen, circ);
                break;
            case TWOCOV :
                this->s_out = BuildFPTwoCovCircuit(this->s_x, this->s_y, this->s_L, this->s_G, this->s_c, this->s_k, this->num, this->bitlen, circ);
                break;
            case PLDA :
                this->s_out = BuildFPPLDACircuit(this->s_x, this->s_y, this->s_L, this->s_G, this->s_k, this->num, this->bitlen, circ);
                break;
        }

		if (this->sharing != S_YAO) {
			this->logResults();
            this->s_out = this->yc->PutB2YGate(this->s_out);
		}

		this->s_out = BuildFPThresholdCircuit(this->s_out, * (uint64_t*) &this->td, this->bitlen, this->yc);

		this->s_out = this->yc->PutOUTGate(this->s_out, ALL);

	} else if (this->dist_type == HAMMING) {
		//use BOOL for Distance
		this->s_out = BuildHammingCircuit(this->s_x, this->s_y, this->num, this->ac);

		this->logResults();

		if (this->sharing == S_YAO) {
			//use YAO sharing for Threshold circuit
			this->s_out = this->yc->PutB2YGate(this->s_out);

            share_p s_t = this->yc->PutCONSGate(static_cast<uint64_t >(this->t), this->bitlen);

            this->s_out = this->yc->PutGTGate(s_t, this->s_out);

			this->s_out = this->yc->PutOUTGate(this->s_out, ALL);
		} else {
			//use BOOL sharing for Threshold circuit
			share_p s_t = this->ac->PutCONSGate(static_cast<uint64_t >(this->t), this->bitlen);

			this->s_out = this->ac->PutGTGate(s_t, this->s_out);

			this->s_out = this->ac->PutOUTGate(this->s_out, ALL);
		}

	} else {
		//INT inputs, use ARITH for computation then YAO for Threshold Cmp
		switch(this->dist_type) {
			case EUCLIDEAN :
				this->s_out = BuildEuclideanCircuit(this->s_x, this->s_y, this->num, this->ac);
				break;
			case COSINE :
				this->s_out = BuildCosineCircuit(this->s_x, this->s_y, this->num, this->ac);
				break;
			case TWOCOV :
				this->s_out = BuildTwoCovCircuit(this->s_x, this->s_y, this->s_L, this->s_G, this->s_c, this->s_k, this->num, this->ac);
				break;
			case PLDA :
				this->s_out = BuildPLDACircuit(this->s_x, this->s_y, this->s_L, this->s_G, this->s_k, this->num, this->ac);
				break;
		}

		this->logResults();

		this->s_out = this->yc->PutA2YGate(this->s_out);

		this->s_out = BuildThresholdCircuit(this->s_out, static_cast<uint64_t >(this->t), this->bitlen, this->yc);
		this->s_out = this->yc->PutOUTGate(this->s_out, ALL);
	}

}

void Biometric::genUnlinkShares() {
	std::vector<Sharing*>& sharings = this->party->GetSharings();
	ArithmeticCircuit *uac =	(ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();
	BooleanCircuit *ubc = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	share* s_ulinky;
	share* s_ulinkout;
	if (this->use_float || this->dist_type == HAMMING)	{
		switch(this->role) {
			case SERVER:
				s_ulinky = ubc->PutSIMDINGate(this->num, inttouint(this->yvals).data(), this->bitlen, this->role);
				break;
			case CLIENT:
				s_ulinky = ubc->PutDummySIMDINGate(this->num, this->bitlen);
				break;
		}

		s_ulinkout = ubc->PutSharedOUTGate(s_ulinky);

	} else {
		switch(this->role) {
			case SERVER:
				s_ulinky = uac->PutSIMDINGate(this->num, inttouint(this->yvals).data(), this->bitlen, this->role);
				break;
			case CLIENT:
				s_ulinky = uac->PutDummySIMDINGate(this->num, this->bitlen);
				break;
		}
		s_ulinkout = uac->PutSharedOUTGate(s_ulinky);
	}

	this->party->ExecCircuit();

	uint32_t out_bitlen, out_nvals;
	uint64_t *out_yvals;

	s_ulinkout->get_clear_value_vec(&out_yvals, &out_bitlen, &out_nvals);

	this->output_ulinky = out_yvals;

	this->party->Reset();
}


void Biometric::runProtocol() {
	this->party->ExecCircuit();

	uint64_t out = this->s_out->get_clear_value<uint64_t>();

	if (this->mode == MODE_ULINK || this->mode == MODE_BIOPER) { //Score Output available only in these modes
		if (this->use_float) {
            uint64_t d = this->s_score->get_clear_value<uint64_t>();
            this->outputd = *(double *) &d;
        }
		else {
            this->output_score = static_cast<long int>(this->s_score->get_clear_value<uint64_t>());
        }
	}

	this->output = !out; //we want out >= thresh but securely computed thresh > out
}

void Biometric::validateOutputs() { //The score will only be shown in Unlinkability or BIOPER mode, otherwise the auth. decision (0/1) is the output
	if (this->use_float) {
		std::cout << "Values: \t" << this->td << " " << this->v_sumd << " " << this->outputd;
		std::cout << "\nVerification Result: \t" << ((this->td < this->v_sumd) ? ACCEPT : REJECT) << std::endl;

		if (this->mode == MODE_ULINK || this->mode == MODE_BIOPER)	{
			std::cout << "Logging: score = " << this->outputd << ", decision: " << (this->output  ? ACCEPT : REJECT) << std::endl;
		}

	} else {
		std::cout << "Values: \t" << this->t << " " << this->v_sum << " " << this->output;
		std::cout << "\nVerification Result: \t" << ((this->t < this->v_sum) ? ACCEPT : REJECT) << std::endl;

		if (this->mode == MODE_ULINK || this->mode == MODE_BIOPER)	{
			std::cout << "Logging: score = " << this->output_score << ", decision: " << (this->output  ? ACCEPT : REJECT) << std::endl;
		}
	}

	if (this->mode == MODE_ULINK) {
		for (int i = 0; i < this->num; ++i)	{
			std::cout << this->output_ulinky[i] << ", ";
		}
		std::cout << "\n";
	}

	std::cout << "Circuit Result:      \t" << (this->output  ? ACCEPT : REJECT) << std::endl;
    std::cout << "\n";
}


std::tuple<uint32_t, double, double, __int128 , __int128 , __int128 , __int128 > Biometric::testBioVer() {
	BiometricFile* bioWriter = 0;
	std::vector<std::tuple<std::string, std::string> > &comparisons = this->bioReader.getComparisons();

	if (this->mode == MODE_ULINK) {
		std::string y_outname("Y");
		std::string z_outname("Z");
		y_outname.append(std::to_string(role));
		z_outname.append(std::to_string(role));

		bioWriter = new BiometricFile(y_outname, z_outname, this->num);
	} else if ((this->mode == MODE_BIOPER || this->mode == MODE_PLAINBIOPER) && this->role == SERVER) {
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        std::ostringstream time;
        time << std::put_time(&tm, "%d-%m-%Y_%H-%M-%S");
		std::string outname("scores_and_decisions-d" + std::to_string(this->dist_type) + "-n" + std::to_string(this->num) + "-m" + std::to_string(this->mode) + "-i" + std::to_string(this->iter) + "-f" + std::to_string(this->use_float)
		    + "-c" + std::to_string(this->subspace) + "-j" + this->comparisons_file  + "-g" + std::to_string(this->sharing) + "_"  + time.str());

		bioWriter = new BiometricFile(outname, this->num, this->use_float);

	}

	int i = 0;
	bool stop = true; //stop if iter iterations are done, or if all possible comparisons found in the comparisons file are done
	while (stop) {
		std::string spID;
		std::string prID;

		if (this->mode == MODE_RNG) {
		    //Using random inputs: only server creates random values, client uses 0 as input
            this->generateRandomInputs();
        } else if (this->role == SERVER) {
		    //Use Input provided by files
		    spID = std::get<0>(comparisons.at(i));
		    prID = std::get<1>(comparisons.at(i));
            this->getInputsFromBioReader(spID, prID);
        }


		if (this->mode == MODE_ULINK)
			this->genUnlinkShares();

		if (this->mode == MODE_PLAINBIOPER) {
			if (this->use_float)
				bioWriter->writeBioPer(spID, prID, this->v_sumd, (this->v_sumd >= this->td), this->dist_type);
			else
            	bioWriter->writeBioPer(spID, prID, this->v_sum, (this->v_sum >= this->t), this->dist_type);

            this->clearInputs();
		} else {
            this->initiateCircuits();
            this->preShareInputs(); //=> use trivial sharing y = y + 0, server knows plaintext, client uses 0 (to simulate pre-sharing)
            this->buildCircuits();
            this->runProtocol();
            //this->validateOutputs(); //for debugging
            if (this->role == SERVER) {
                if (this->use_float)
                	if (this->mode == MODE_BIOPER)
                		this->errors += this->outputd != this->v_sumd; //check if scores match
					else
                    	this->errors += this->output != (this->v_sumd >= this->td); //check if authentication decisions match
                else {
                    if (this->mode == MODE_BIOPER)
                        this->errors += this->output_score != this->v_sum;
                    else
                        this->errors += this->output != (this->v_sum >= this->t);
                }

            } else {
                this->errors = -1; //Client can't verify because it doesn't know the plain values
            }


            this->online_time += this->party->GetTiming(P_ONLINE);
            this->total_time += this->party->GetTiming(P_TOTAL);
            this->online_bytes_sent += this->party->GetSentData(P_ONLINE);
            this->total_bytes_sent += this->party->GetSentData(P_TOTAL);
            this->online_bytes_recv += this->party->GetReceivedData(P_ONLINE);
            this->total_bytes_recv += this->party->GetReceivedData(P_TOTAL);

            this->clearInputs();
            this->party->Reset();

            if (this->mode == MODE_ULINK) {
                /* Log Y1/2 and Z1/2 */
                if (i < this->iter/2) { //Application A
                    bioWriter->writeUlinkA(spID, prID, this->output_ulinky, this->output_score);
                } else { //Application B
                    bioWriter->writeUlinkB(spID, prID, this->output_ulinky, this->output_score);
                }
            }  else if (this->mode == MODE_BIOPER && this->role == SERVER) {
            	if (this->use_float)
					bioWriter->writeBioPer(spID, prID, this->outputd, this->output, this->dist_type);
            	else
                	bioWriter->writeBioPer(spID, prID, this->output_score, this->output, this->dist_type);
            }
		}



		i++;
        if (this->mode != MODE_RNG && this->role == SERVER)
            stop = i < this->iter && i < comparisons.size();
        else
            stop = i < this->iter;
	}

	if (this->mode == MODE_ULINK || (this->mode == MODE_BIOPER || this->mode == MODE_PLAINBIOPER) && this->role==SERVER)
		delete bioWriter;

	return {this->errors, this->online_time, this->total_time, this->online_bytes_sent, this->total_bytes_sent, 
		this->online_bytes_recv, this->total_bytes_recv};
}

void Biometric::clearInputs() {
    this->xvals.clear();
    this->xvalsF.clear();
    this->yvals.clear();
    this->yvalsF.clear();
    this->L.clear();
    this->G.clear();
    this->c.clear();
    this->LF.clear();
    this->GF.clear();
    this->cF.clear();
    this->v.clear();
    this->s_L.clear();
    this->s_G.clear();
}

Biometric::~Biometric() {
	delete this->party;
}