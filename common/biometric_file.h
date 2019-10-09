/**
 \file 		biometric_file.h
 \author 	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementation of biometric file reader/writer for class biometric
 */

#ifndef __BIOMETRIC_FILE_H_
#define __BIOMETRIC_FILE_H_

#include <math.h>
#include <cassert>
#include <map>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>

/*
	Class BiometricFile opens a file with biometric templates/embeddings (i-vectors) and extracts the values.
	Can also be used to store resulting values
*/
class BiometricFile {
	std::map<std::string, std::vector<long int> > references;
	std::map<std::string, std::vector<double> > referencesF;
	std::map<std::string, std::vector<long int> > probes;
	std::map<std::string, std::vector<double> > probesF;
	std::vector<std::tuple<std::string, std::string> > comparisons;
	uint32_t num;
	bool use_float;

	std::vector<std::vector<long int> > L, G;
	std::vector<std::vector<double> > LF, GF;
	std::vector<long int> c;
	std::vector<double> cF;
	long int k;
	double kF;

	std::ofstream bioper_outfile;
	std::ofstream y_a_outfile;
	std::ofstream y_b_outfile;
	std::ofstream z_a_outfile;
	std::ofstream z_b_outfile;
public:

	BiometricFile();
	BiometricFile(bool use_float);
	BiometricFile(uint32_t num, bool use_float = false); //For setting up readers
	BiometricFile(std::string out, uint32_t num, bool use_float = false); //For writing regular outputs
	BiometricFile(std::string out, std::string out2, uint32_t num); //For unlinkability Analysis

	void readComparisons(std::string infilename);
	void readReferences(std::string infilename);
	void readProbes(std::string infilename);
	void read2CovModel(std::string ink,std::string inc, std::string inL, std::string inG);
    void readPLDAModel(std::string ink, std::string inL, std::string inG);

	void setNum(uint32_t num);
	void setUseFloat(bool val);

	std::vector<std::tuple<std::string, std::string>> &getComparisons();
	std::vector<long int> &getReference(std::string id);
	std::vector<double> &getReferenceF(std::string id);
	std::vector<long int> &getProbe(std::string id);
	std::vector<double> &getProbeF(std::string id);

    std::vector<long int> &getC();
	std::vector<double> &getCF();
    std::vector<long int> &getLLine(uint32_t pos);
	std::vector<double> &getLLineF(uint32_t pos);
    std::vector<long int> &getGLine(uint32_t pos);
    std::vector<double> &getGLineF(uint32_t pos);
	long int getK();
	double getKF();

	void writeUlinkA(std::string speakerID, std::string probeID, uint64_t* y, uint64_t z);
	void writeUlinkB(std::string speakerID, std::string probeID, uint64_t* y, uint64_t z);

	void writeBioPer(std::string speakerID, std::string probeID, long int z, uint64_t d, uint32_t dist_type);
	void writeBioPer(std::string speakerID, std::string probeID, double z, uint64_t d, uint32_t dist_type);

	~BiometricFile();
	
};


#endif
