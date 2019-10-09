/**
 \file 		asv_test.cpp
 \author	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementing outsourced score computation tests for automatic speaker verification
 */

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/aby/abyparty.h"

#include <set>

#include "common/biometric.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
		uint16_t* port, uint32_t* dist, uint32_t* use_float, uint32_t* iter, uint32_t* mode, std::string *thresh, std::string *comparisons, uint32_t *subspace, uint32_t *share_type) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
              {	(void*) bitlen, T_NUM, "b", "Bit-length, default 64", false, false },
			  { (void*) nvals, T_NUM, "n",	"Number of elements of an i-vector (has to be 50, 100, 150, 200, 250, 400, 600)", false, false },
			  { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			  {	(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			  {	(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			  { (void*) dist, T_NUM, "d", "Distance used for verification, 0=EUCLIDEAN, 1=COSINE, 2=HAMMING, 3=TWOCov/non-centered PLDA, 4=centered PLDA, default: 1", false, false},
			  { (void*) use_float, T_NUM, "f", "Bit indicating whether the operations should be floating point, 0=INT, 1=FLOAT, default: 0", false, false},
			  { (void*) iter, T_NUM, "i",	"Number of iterations for benchmarking, default: 1", false, false },
			  { (void*) mode, T_NUM, "m",	"Mode of operation, 0: benchmarking i-vector challenge data over i samples, 1: unlinkability of i-vector challenge data over the first i samples (store shares Y2 & Z2 (score)), 2: biometric performance of i-vector challenge data over first i combinations of the comparisons file (store score & decision), 3: use random values and benchmark i iterations, 4: plain biometric performance of i-vector challenge data over first i combinations of the comparisons file (log score & decision) in plaintext, default: 0 , optional", false, false },
			  { (void*) thresh, T_STR, "t",	"64-bit INT threshold for verif., has to be given as an int, default: log(99) *10^5", false, false },
              { (void*) comparisons, T_STR, "j",	"Comparison file name, default: comparisons", false, false },
              { (void*) subspace, T_NUM, "c",	"PLDA Subspace dimension, default: 25", false, false },
              { (void*) share_type, T_NUM, "g",	"Use Yao's GC for the entire computation (only possible if floats are used), default=0", false, false }};


	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		std::cout << "Exiting" << std::endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	return 1;
}

//show thousands separator
std::string printBytes(long int  in) {
	std::string s = std::to_string(in);
	for (long int  i = s.length()-3; i>0 ;i=i-3)	{
		s.insert(i, ",");
	}
	return s;
}

int main(int argc, char** argv) {
	//set default parameters
	e_role role;
	uint32_t bitlen = 64, nvals = 250, secparam = 128, nthreads = 1, iter=1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	uint32_t dist = COSINE;
	uint32_t use_float = USE_INT;
	uint32_t share_type = 0;
	e_mt_gen_alg mt_alg = MT_OT;
	uint32_t mode = MODE_RTIME;
	std::string thresh = "199563";
	std::string comparisons = "comparisons";
	uint32_t subspace = 25;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port,  &dist, &use_float, &iter, &mode, &thresh, &comparisons, &subspace, &share_type);

	if (dist >= DISTANCE_LAST)	{
		std::cout << "Incorrect -d distance parameter, using default 1 (COSINE)" << std::endl;
		dist = COSINE;
	}
	if (use_float > USE_FLOAT)	{
		std::cout << "Incorrect -f float parameter, using default 0 (INT)" << std::endl;
		use_float = USE_INT;
	}
	if (share_type >= S_ARITH)	{
		std::cout << "Incorrect -g sharing type parameter, using default 0" << std::endl;
		share_type = 0;
	}
	if (mode >= MODE_LAST)	{
		std::cout << "Incorrect -m operation mode parameter, using default 0 (RUNTIME)" << std::endl;
		mode = MODE_RTIME;
	}
	std::set<uint16_t> allowedDims = {50, 100, 150, 200, 250, 400, 600};
	std::set<uint16_t>::iterator it = allowedDims.find(nvals);
	if (it == allowedDims.end())	{
		std::cout << "Incorrect -n i-vector dimension parameter, has to be in (50, 100, 150, 200, 250, 400, 600), using default 250 " << std::endl;
		nvals = 250;
	}


	seclvl seclvl = get_sec_lvl(secparam);

	Biometric bio(role, (char*) address.c_str(), port, seclvl, bitlen, nthreads, mt_alg, nvals, static_cast<e_sharing>(share_type), dist, use_float, iter, mode, std::stol(thresh), comparisons, subspace);

	auto [errors, online_time, total_time, online_bytes_sent, total_bytes_sent, 
			online_bytes_recv, total_bytes_recv] = bio.testBioVer();

	std::string role_str;
	switch(role) {
		case CLIENT:
			role_str = "Client";
			break;
		case SERVER:
			role_str = "Server";
			break;
	}

	std::cout << "\nEvaluated " << iter << " verification iterations as " << role_str << ", resulting in " << errors << " errors!" << std::endl;
	std::cout << "Mean online time was " << online_time/iter << " ms and mean total time was " << total_time/iter << " ms." << std::endl;
	std::cout << "Mean online sent was " << printBytes(online_bytes_sent/iter) << " Bytes and mean total sent was " << printBytes(total_bytes_sent/iter) << " Bytes." << std::endl;
	std::cout << "Mean online received was " << printBytes(online_bytes_recv/iter) << " Bytes and mean total recv was " << printBytes(total_bytes_recv/iter) << " Bytes." << std::endl;
	std::cout << "=> Mean online Communication was " << printBytes(online_bytes_sent/iter + online_bytes_recv/iter) << " Bytes, " << online_time/iter << " ms and mean total communication was " << 
				printBytes(total_bytes_sent/iter + total_bytes_recv/iter) << " Bytes, " << total_time/iter << " ms." << std::endl;
	return 0;
}