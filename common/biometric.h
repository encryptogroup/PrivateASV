/**
 \file 		biometric.h
 \author 	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementation of biometric distance/score threshold verification using ABY Framework.
 */

#ifndef __BIOMETRIC_H_
#define __BIOMETRIC_H_

#define ACCEPT 	"ACCEPT"
#define REJECT 	"REJECT"
#define EUCLIDEAN 0
#define COSINE 1
#define HAMMING 2
#define TWOCOV 3
#define PLDA 4
#define DISTANCE_LAST 5
#define USE_INT 0
#define USE_FLOAT 1
#define MODE_RTIME 0
#define MODE_ULINK 1
#define MODE_BIOPER 2
#define MODE_RNG 3
#define MODE_PLAINBIOPER 4
#define MODE_LAST 5

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/sharing/sharing.h"
#include "biometric_file.h"
#include "CircuitWrapper.h"
#include <math.h>
#include <cassert>
#include <chrono>
#include <ctime>
#include <iomanip>
/*
	Class Biometric creates an ABYParty and circuits. Using testBioVer(), one can run a verification on data
	using dist_type as score, and validate the circuit output with the real one.
*/
class Biometric {
	e_role role;
	uint16_t use_float, dist_type, mode;
	uint32_t num, iter, errors, subspace, bitlen;
	double online_time, total_time;
    __int128  online_bytes_sent, online_bytes_recv;
    __int128  total_bytes_sent, total_bytes_recv;
	std::vector<long int > xvals, yvals;
	std::vector<double > xvalsF, yvalsF;
	std::vector<uint64_t > dummyvals;
	long int v_sum, output, output_score;
	long int t;
	double v_sumd, td, outputd;
	e_sharing sharing;
	ABYParty* party;
	CircuitW_p ac;
	CircuitW_p yc;
	share_p s_x, s_y, s_out;
	std::vector<share_p> s_L, s_G;
	share_p s_c, s_k;
	share_p s_score;
	uint64_t *output_ulinky;
	std::vector<std::vector<long int >> L, G;
	std::vector<std::vector<double >> LF, GF;
	std::vector<long int > c;
	std::vector<double > cF;
    long int k;
	double kF;
	std::vector<double> v;
	BiometricFile bioReader;
	std::string comparisons_file;
public:
	/**
	\param	role 		role played by the program which can be server or client part.
	\param 	address 	IP Address
	\param  port   		port
	\param  seclvl 		Security level
	\param 	bitlen		Bit length of the inputs
	\param 	nthreads	Number of threads
	\param	mt_alg		The algorithm for generation of multiplication triples
	\param 	num			the number of elements in a biometric feature vector
	\param 	sharing		Sharing type (S_YAO to use YAO for entire computation with full floating point operations)
	\param	dist_type	Type of distance/score to be used
	\param	use_float   operate on integers or double
	\param	iter        number of times the protocol is run (to get a mean of the results)
	\param  mode        Mode of operation (benchmarking, unlinkability, biometric performance, plaintext computation)
	\param  thresh      Threshold used for the comparison
	\param	comparison_file	name of file to read to obtain speakerID and probeID pairs that have to be matched
	\param  subspace    PLDA subspace (to obtain correct input file)
	\brief	This function is used for setting up a testing environment for threshold verification of biometric/speech data using
	 		score dist_type
	*/
	Biometric(e_role role, char* address, uint16_t port, seclvl seclvl, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, 
		uint32_t num, e_sharing sharing, uint16_t dist_type, uint16_t use_float, uint32_t iter, uint16_t mode, long int thresh, std::string comparison_file, uint32_t subspace);
	/**
	\brief	This function runs iter iterations of the privacy-preserving biometric verification protocol in the specified mode
			using score dist_type. It returns errors, online_time, total_time, online_bytes_sent, total_bytes_sent,
			online_bytes_recv, total_bytes_recv.
	*/
	std::tuple<uint32_t, double, double, __int128 , __int128 , __int128 , __int128 > testBioVer();
	~Biometric();
private:
    /**
     \brief Compute Plain PLDA results
     */
    void computePlain();
	void generateRandomInputs();
	void getInputsFromBioReader(std::string, std::string);
	void initiateCircuits();
    /**
    \brief Convert Pre-Shared Boolean to Yao
    */
    void inputB2Y();
	void preSharePLDA();
	void preShareInputs();
	void logResults();
	void buildCircuits();
    /**
    \brief Output shares of Y and Z (the score) across applications to simulate generated shares. This can be used to perform Unlinkability analysis
    */
    void genUnlinkShares();
	void runProtocol();
	/**
	\brief	This function prints the plaintext results, use only for debugging
	*/
	void validateOutputs();
	void clearInputs();
};


#endif
