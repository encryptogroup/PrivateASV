/**
 \file 		biometric_distances.h
 \author 	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementation of biometric distances/scores + help functions on circuits using ABY Framework.
 */

#ifndef __BIOMETRIC_DIST_H_
#define __BIOMETRIC_DIST_H_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/sharing/sharing.h"
#include "CircuitWrapper.h"
#include <math.h>
#include <cassert>

/**
 \param		x
 \param		y 
 \brief		Compute the Hamming distance of x and y (plaintext) using Brian Kernighan's Algorithm
 */
int HammingDist(long int x, long int y);


/**
 \param		x
 \param		y 
 \param		L
 \param		G
 \param		c
 \param		k
 \param 	num
 \brief		Compute the 2Cov/non-centered PLDA score of embeddings x and y, Model Matrices L and G, vector c and constant k (plaintext)
 */
long int TwoCovDist(std::vector<long int> &x, std::vector<long int> &y, std::vector<std::vector<long int>> &L, std::vector<std::vector<long int>> &G, std::vector<long int > &c, long int k, uint32_t num);
double TwoCovDist(std::vector<double> &x, std::vector<double> &y, std::vector<std::vector<double>> &L, std::vector<std::vector<double>> &G, std::vector<double> &c, double k, uint32_t num);

/**
 \param		x
 \param		y 
 \param		L
 \param		G
 \param		k
 \param		num
 \brief		Compute the PLDA (centered) score of embeddings x and y, Model Matrices L and G, and constant k (plaintext)
 */
long int PLDADist(std::vector<long int> &x, std::vector<long int> &y, std::vector<std::vector<long int>> &L, std::vector<std::vector<long int>> &G, long int k, uint32_t num);
double PLDADist(std::vector<double > & x, std::vector<double> & y, std::vector<std::vector<double>> & Q, std::vector<std::vector<double>> & P, double k, uint32_t num);

/**
 \param		x
 \param		y 
 \param		res
 \param		num
 \brief		Compute Vector addition of x and y (plaintext) on vector res
 */
std::vector<long int > VecAdd(std::vector<long int > &x, std::vector<long int > &y, uint32_t num);
std::vector<double > VecAdd(std::vector<double > &x, std::vector<double > &y, uint32_t num);


/**
 \param		x
 \param		y 
 \param		num
 \brief		Compute (Inner) Vector Product of x and y (plaintext)
 */
long int VecProd(std::vector<long int > &x, std::vector<long int > &y, uint32_t num);
double VecProd(std::vector<double> &x, std::vector<double> &y, uint32_t num);


/**
 \param		M
 \param		v 
 \param		num
 \param		res
 \brief		Compute Matrix-Vector Dot Product M*v (plaintext) in vector res
 */
std::vector<long int> DotProd(std::vector<std::vector<long int >> &  M, std::vector<long int > &v, uint32_t num);
std::vector<double> DotProd(std::vector<std::vector<double >> &  M, std::vector<double> & v, double num);

/**
 \param		s_x			share of X values (Client feature vector)
 \param		s_y 		share of Y values (DB's reference feature vector)
 \param 	num			the number of elements in a feature vector
 \param		bc	 		Boolean Circuit object.
 \brief		This function is used to compute the Hamming distance of X and Y.
 */
share_p BuildHammingCircuit(share_p s_x, share_p s_y, uint32_t num, CircuitW_p bc);

/**
 \param		s_x			share of X values (Client feature vector)
 \param		s_y 		share of Y values (DB's reference feature vector)
 \param 	num			the number of elements in a feature vector
 \param		ac	 		Circuit object.
 \brief		This function is used to compute the Cosine distance of X and Y. Note that this implementation does not compute
 			the normalization, i.e., inputs to s_x and s_y have to correspond to X/||X|| and Y/||Y|| to correctly compute the distance
 */
share_p BuildCosineCircuit(share_p s_x, share_p s_y, uint32_t num, CircuitW_p ac);

/**
 \param		s_x			share of X values (Client feature vector)
 \param		s_y 		share of Y values (DB's reference feature vector)
 \param 	num			the number of elements in a feature vector
 \param		ac	 		Circuit object.
 \brief		This function is used to compute the Euclidean distance of X and Y.
 */
share_p BuildEuclideanCircuit(share_p s_x, share_p s_y, uint32_t num, CircuitW_p ac);


/**
 \param		x
 \param		y 
 \param		L
 \param		G
 \param		c
 \param		k
 \param		ac
 \brief		Compute the 2Cov/non-centered PLDA score of embedding shares s_x and s_y, shared Model Matrices s_L and s_G, vector share s_c, and constant share s_k
 */
share_p BuildTwoCovCircuit(share_p s_x, share_p s_y, std::vector<share_p > s_L, std::vector<share_p > s_G, share_p s_c, share_p s_k, uint32_t num, CircuitW_p ac);

/**
 \param		x
 \param		y 
 \param		L
 \param		G
 \param		k
 \param		ac
 \brief		Compute the PLDA (centered) score of embedding shares s_x and s_y, shared Model Matrices s_L and s_G, and constant share s_k
*/
share_p BuildPLDACircuit(share_p s_x, share_p s_y, std::vector<share_p > s_L, std::vector<share_p > s_G, share_p s_k, uint32_t num, CircuitW_p ac);


/**
 \param		s_dist		share of the computed distance value of X and Y
 \param		t		    threshold value
 \param		bc	 		Boolean Circuit object.
 \brief		This function is used to compute whether the value of s_dist passes the verification, i.e., if t>=dist.
 */
share_p BuildThresholdCircuit(share_p s_dist, uint64_t t, uint32_t bitlen, CircuitW_p bc);


/**
 \param		s_M			share of SIMD Matrix M
 \param		s_v		    share of SIMD vector v
 \param		num	 		dimension of M and v
 \param		ac 			Arithmetic or Boolean Circuit
 \brief		This function is used to securely compute the Matrix-Vector Dot-Product M*v
 */
share_p putDotGate(std::vector<share_p > s_m, share_p s_v, uint32_t num, CircuitW_p ac);

/**
 \param		s_simd		share of SIMD values
 \param		num		    dimension of SIMD values
 \param		cw	 		Boolean Circuit object.
 \brief		This function is used to compute the sum of all values in s_simd.
 */
share_p putSumGate(share_p s_simd, uint32_t num, CircuitW_p ac);

/**
 the following functions compute the same operations on FP input
 */
share_p putFPDotGate(std::vector<share_p> s_m, share_p s_v, uint32_t num, uint32_t bitlen, CircuitW_p bc);

share_p BuildFPCosineCircuit(share_p s_x, share_p s_y, uint32_t num, uint32_t bitlen, CircuitW_p bc);

share_p BuildFPEuclideanCircuit(share_p s_x, share_p s_y, uint32_t num, uint32_t bitlen, CircuitW_p bc);

share_p BuildFPTwoCovCircuit(share_p s_x, share_p s_y, std::vector<share_p> s_L, std::vector<share_p>s_G, share_p s_c, share_p s_k, uint32_t num, uint32_t bitlen, CircuitW_p bc);

share_p BuildFPPLDACircuit(share_p s_x, share_p s_y, std::vector<share_p> s_Q, std::vector<share_p> s_P, share_p s_k, uint32_t num, uint32_t bitlen, CircuitW_p bc);

share_p BuildFPThresholdCircuit(share_p s_dist, uint64_t t, uint32_t bitlen, CircuitW_p bc);

share_p putFPSumGate(share_p s_simd, uint32_t num, uint32_t bitlen, CircuitW_p bc);

/**
 the following function transforms the vector of shares with num dimensions into one SIMD Share
 */
share_p toSIMD(std::vector<share_p > s, uint32_t num, CircuitW_p ac, e_sharing sharing = S_ARITH);

#endif