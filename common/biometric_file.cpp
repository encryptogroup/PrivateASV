/**
 \file 		biometric_file.cpp
 \author 	treiber@encrypto.cs.tu-darmstadt.de
 \copyright	 Copyright (C) 2019 Cryptography and Privacy Engineering Group, TU Darmstadt
 \brief		Implementation of biometric file reader/writer for class biometric
 */

#include "biometric_file.h"
#include "biometric.h"

void checkInFile(std::ifstream& stream, std::string fname) {
    if (! stream.good())
        std::cout << "WARNING: Trying to open file '" + fname + "' but failed.";
}

void checkOutFile(std::ofstream& stream, std::string fname) {
    if (! stream.is_open())
        std::cout << "WARNING: Trying to write to file '" + fname + "' but failed.";
}

BiometricFile::BiometricFile() {
    this->use_float = false;
}

BiometricFile::BiometricFile(bool use_float) {
    this->use_float = use_float;
}

BiometricFile::BiometricFile(uint32_t num, bool use_float) {
    this->num = num;
    this->use_float = use_float;
}

BiometricFile::BiometricFile(std::string out, uint32_t num, bool use_float) {
    this->num = num;
    this->use_float = use_float;
    this->bioper_outfile.open(out);
    checkOutFile(this->bioper_outfile, out);
}

BiometricFile::BiometricFile(std::string out, std::string out2, uint32_t num) { //out: Y, out2: Z, for unlinkability analysis
    this->y_a_outfile.open(out + "A");
    checkOutFile(this->y_a_outfile, out + "A");
    this->z_a_outfile.open(out2 + "A");
    checkOutFile(this->z_a_outfile, out2 + "A");
    this->y_b_outfile.open(out + "B");
    checkOutFile(this->y_b_outfile, out + "B");
    this->z_b_outfile.open(out2 + "B");
    checkOutFile(this->z_b_outfile, out2 + "B");

    this->num = num;
}

void BiometricFile::readComparisons(std::string infilename) {
    std::ifstream infile;
    infile.open(infilename);
    checkInFile(infile, infilename);
    std::string line;
    if (infile.is_open()) {
        while (std::getline(infile, line)) {
            std::size_t found = line.find(",");
            if (found!=std::string::npos) {
                //found + 1 to get rid of the comma
                this->comparisons.push_back({line.substr(0, found),line.substr(found+1)});
            }
        }
    }
    infile.close();

}

void BiometricFile::readReferences(std::string infilename) {

    std::ifstream infile;
    infile.open(infilename);
    checkInFile(infile, infilename);
    std::string line;

    if (this->use_float) {
        if (infile.is_open()) {
            while (std::getline(infile, line)) {
                std::size_t found = line.find(","); //first occurence
                std::size_t prev_found = found;
                std::string speakerID = "";
                if (found!=std::string::npos)
                    speakerID = line.substr(0, found);
                std::vector<double> v;
                while (found!=std::string::npos && v.size() < this->num ) {
                    found = line.find(" ", found + 1);

                    if (found!=std::string::npos) {
                        v.push_back(std::stod(line.substr(prev_found + 1, found - prev_found - 1)));
                        prev_found = found;
                    }
                }
                //add last element
                std::string lastelem = line.substr(prev_found + 1, line.length() - prev_found - 1);
                if (!lastelem.empty() && v.size() < this->num)
                    v.push_back(std::stod(lastelem));

                assert(v.size() == this->num);
                this->referencesF.insert( std::pair<std::string, std::vector<double > >(speakerID, v));

            }
        }

    } else {
        if (infile.is_open()) {
            while (std::getline(infile, line)) {
                std::size_t found = line.find(","); //first occurence
                std::size_t prev_found = found;
                std::string speakerID = "";
                if (found!=std::string::npos)
                    speakerID = line.substr(0, found);
                std::vector<long int> v;
                while (found!=std::string::npos && v.size() < this->num ) {
                    found = line.find(" ", found + 1);

                    if (found!=std::string::npos) {
                        v.push_back((long int) (100000 * std::stof(line.substr(prev_found + 1, found - prev_found - 1))));
                        prev_found = found;
                    }
                }
                //add last element
                std::string lastelem = line.substr(prev_found + 1, line.length() - prev_found - 1);
                if (!lastelem.empty() && v.size() < this->num)
                    v.push_back((long int) (100000 * std::stof(lastelem)));

                assert(v.size() == this->num);
                this->references.insert( std::pair<std::string, std::vector<long int> >(speakerID, v));

            }
        }
    }

    infile.close();

}

void BiometricFile::readProbes(std::string infilename) {
    std::ifstream infile;
    infile.open(infilename);
    checkInFile(infile, infilename);
    std::string line;

    if (this->use_float) {
        if (infile.is_open()) {
            while (std::getline(infile, line)) {
                std::size_t found = line.find(","); //first occurence
                std::size_t prev_found = found;
                std::string speakerID = "";
                if (found!=std::string::npos)
                    speakerID = line.substr(0, found);
                std::vector<double> v;
                while (found!=std::string::npos) {
                    found = line.find(" ", found + 1);

                    if (found!=std::string::npos) {
                        v.push_back(std::stod(line.substr(prev_found + 1, found - prev_found - 1)));
                        prev_found = found;
                    }
                }
                //add last element
                std::string lastelem = line.substr(prev_found + 1, line.length() - prev_found - 1);
                if (!lastelem.empty() && v.size() < this->num)
                    v.push_back(std::stod(lastelem));

                assert(v.size() == this->num);
                this->probesF.insert( std::pair<std::string, std::vector<double> >(speakerID, v));
            }
        }
    } else {
        if (infile.is_open()) {
            while (std::getline(infile, line)) {
                std::size_t found = line.find(","); //first occurence
                std::size_t prev_found = found;
                std::string speakerID = "";
                if (found!=std::string::npos)
                    speakerID = line.substr(0, found);
                std::vector<long int> v;
                while (found!=std::string::npos) {
                    found = line.find(" ", found + 1);

                    if (found!=std::string::npos) {
                        v.push_back((long int) (100000 * std::stof(line.substr(prev_found + 1, found - prev_found - 1))));
                        prev_found = found;
                    }
                }
                //add last element
                std::string lastelem = line.substr(prev_found + 1, line.length() - prev_found - 1);
                if (!lastelem.empty() && v.size() < this->num)
                    v.push_back((long int) (100000 * std::stof(lastelem)));

                assert(v.size() == this->num);
                this->probes.insert( std::pair<std::string, std::vector<long int> >(speakerID, v));
            }
        }
    }

    infile.close();

}

void BiometricFile::read2CovModel(std::string ink,std::string inc, std::string inL, std::string inG) {
    std::ifstream kfile;
    std::string line;
    kfile.open(ink);
    checkInFile(kfile, ink);

    if (this->use_float) {
        if (kfile.is_open())  {
            while (std::getline(kfile, line)) {
                this->kF = std::stod(line);
            }
        }
    } else {
        if (kfile.is_open())  {
            while (std::getline(kfile, line)) {
                this->k = (long int) (static_cast<double>(1e15) * std::stod(line));
            }
        }
    }

    std::ifstream cfile;
    cfile.open(inc);
    checkInFile(cfile, inc);

    if (this->use_float) {
        if (cfile.is_open())  {
            while (std::getline(cfile, line)) {
                this->cF.push_back(std::stof(line));
            }
        }
        assert(this->cF.size() == this->num);
    } else {
        if (cfile.is_open())  {
            while (std::getline(cfile, line)) {
                this->c.push_back((long int) (1e10* std::stof(line)));
            }
        }
        assert(this->c.size() == this->num);
    }

    std::ifstream Lfile;
    Lfile.open(inL);
    checkInFile(Lfile, inL);
    if (this->use_float) {
        if (Lfile.is_open())  {
            while (std::getline(Lfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<double> v;
                while (found!=std::string::npos) {
                    v.push_back(std::stod(line.substr(prev_found, found - prev_found)));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() && v.size() < this->num) {
                    v.push_back(std::stod(line.substr(prev_found, line.length() - prev_found)));
                }

                assert(v.size() == this->num);
                this->LF.push_back(v);
            }

        }
    } else {
        if (Lfile.is_open())  {
            while (std::getline(Lfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<long int> v;
                while (found!=std::string::npos) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, found - prev_found))));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() && v.size() < this->num) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, line.length() - prev_found))));
                }

                assert(v.size() == this->num);
                this->L.push_back(v);
            }

        }
    }


    std::ifstream Gfile;
    Gfile.open(inG);
    checkInFile(Gfile, inG);
    if (this->use_float) {

        if (Gfile.is_open())  {
            while (std::getline(Gfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<double> v;
                while (found!=std::string::npos) {
                    v.push_back(std::stod(line.substr(prev_found, found - prev_found)));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() ) {
                    v.push_back(std::stod(line.substr(prev_found, line.length() - prev_found)));
                }

                assert(v.size() == this->num);
                this->GF.push_back(v);
            }
        }
    } else {

        if (Gfile.is_open())  {
            while (std::getline(Gfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<long int> v;
                while (found!=std::string::npos) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, found - prev_found))));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() ) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, line.length() - prev_found))));
                }

                assert(v.size() == this->num);
                this->G.push_back(v);
            }
        }
    }


}

void BiometricFile::readPLDAModel(std::string ink, std::string inL, std::string inG) {
    std::ifstream kfile;
    std::string line;
    kfile.open(ink);
    checkInFile(kfile, ink);

    if (this->use_float) {
        if (kfile.is_open())  {
            while (std::getline(kfile, line)) {
                this->kF = std::stod(line);
            }
        }

    } else {
        if (kfile.is_open())  {
            while (std::getline(kfile, line)) {
                this->k = (long int) (static_cast<double>(1e15)* std::stod(line));
            }
        }

    }


    std::ifstream Lfile;
    Lfile.open(inL);
    checkInFile(Lfile, inL);

    if (this->use_float) {
        if (Lfile.is_open())  {
            while (std::getline(Lfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<double> v;
                while (found!=std::string::npos && v.size() < this->num) {

                    v.push_back(std::stod(line.substr(prev_found, found - prev_found)));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() && v.size() < this->num) {
                    v.push_back(std::stod(line.substr(prev_found, line.length() - prev_found)));
                }

                assert(v.size() == this->num);
                this->LF.push_back(v);
            }

        }
    } else {
        if (Lfile.is_open())  {
            while (std::getline(Lfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<long int> v;
                while (found!=std::string::npos && v.size() < this->num) {

                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, found - prev_found))));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() && v.size() < this->num) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, line.length() - prev_found))));
                }

                assert(v.size() == this->num);
                this->L.push_back(v);
            }

        }
    }

    std::ifstream Gfile;
    Gfile.open(inG);
    checkInFile(Gfile, inG);

    if (this->use_float) {
        if (Gfile.is_open())  {
            while (std::getline(Gfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<double> v;
                while (found!=std::string::npos) {
                    v.push_back(std::stod(line.substr(prev_found, found - prev_found)));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() && v.size() < this->num) {
                    v.push_back(std::stod(line.substr(prev_found, line.length() - prev_found)));
                }

                assert(v.size() == this->num);
                this->GF.push_back(v);
            }
        }
    } else {

        if (Gfile.is_open())  {
            while (std::getline(Gfile, line)) {
                std::size_t found = line.find(" ");
                std::size_t prev_found = 0;
                std::vector<long int> v;
                while (found!=std::string::npos) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, found - prev_found))));
                    prev_found = found + 1;

                    found = line.find(" ", prev_found);
                }
                //last elem
                if (prev_found < line.length() && v.size() < this->num) {
                    v.push_back((long int) (100000* std::stof(line.substr(prev_found, line.length() - prev_found))));
                }

                assert(v.size() == this->num);
                this->G.push_back(v);
            }
        }
    }

}

std::vector<long int> &BiometricFile::getC() {
    return this->c;
}

std::vector<double> &BiometricFile::getCF() {
    return this->cF;
}

std::vector<long int> &BiometricFile::getLLine(uint32_t pos) {
    return this->L.at(pos);
}

std::vector<double> &BiometricFile::getLLineF(uint32_t pos) {
    return this->LF.at(pos);
}

std::vector<long int> &BiometricFile::getGLine(uint32_t pos) {
    return this->G.at(pos);
}

std::vector<double> &BiometricFile::getGLineF(uint32_t pos) {
    return this->GF.at(pos);
}

long int BiometricFile::getK() {
    return this->k;
}

double BiometricFile::getKF() {
    return this->kF;
}

std::vector<std::tuple<std::string, std::string> > &BiometricFile::getComparisons() {
    return this->comparisons;
}

std::vector<long int> &BiometricFile::getReference(std::string id) {
    assert(this->references.count(id) == 1);
    return this->references.at(id);
}

std::vector<double> &BiometricFile::getReferenceF(std::string id) {
    assert(this->referencesF.count(id) == 1);
    return this->referencesF.at(id);
}

std::vector<long int> &BiometricFile::getProbe(std::string id) {
    assert(this->probes.count(id) == 1);
    return this->probes.at(id);
}

std::vector<double> &BiometricFile::getProbeF(std::string id) {
    assert(this->probesF.count(id) == 1);
    return this->probesF.at(id);
}

void BiometricFile::setNum(uint32_t num) {
    this->num = num;
}

void BiometricFile::setUseFloat(bool val) {
    this->use_float = val;
}

void BiometricFile::writeUlinkA(std::string speakerID, std::string probeID, uint64_t* y, uint64_t z) {
    if (this->y_a_outfile.is_open())	{
        this->y_a_outfile << speakerID << "," << probeID << ",";
        for (int i = 0; i < this->num; ++i)	{
            this->y_a_outfile << y[i] << " ";
        }
        this->y_a_outfile << std::endl;
    }

    if (this->z_a_outfile.is_open())	{
        this->z_a_outfile << speakerID << "," << probeID << "," << z << std::endl;
    }
}
void BiometricFile::writeUlinkB(std::string speakerID, std::string probeID, uint64_t* y, uint64_t z) {
    if (this->y_b_outfile.is_open())	{
        this->y_b_outfile << speakerID << "," << probeID << ",";
        for (int i = 0; i < this->num; ++i)	{
            this->y_b_outfile << y[i] << " ";
        }
        this->y_b_outfile << std::endl;
    }

    if (this->z_b_outfile.is_open())	{
        this->z_b_outfile << speakerID << "," << probeID << "," << z << std::endl;
    }
}

void BiometricFile::writeBioPer(std::string speakerID, std::string probeID, long int z, uint64_t d, uint32_t dist_type) {

    double out;

    if (dist_type == EUCLIDEAN || dist_type == COSINE) {
        out = static_cast<double>(z)/1e10;
    } else { //PLDA
        out = static_cast<double>(z)/1e15;
    }

    if (this->bioper_outfile.is_open())	{
        this->bioper_outfile << speakerID << "," << probeID << "," << out << "," << d << std::endl;
    }
}

void BiometricFile::writeBioPer(std::string speakerID, std::string probeID, double z, uint64_t d, uint32_t dist_type) {

    if (this->bioper_outfile.is_open())	{
        this->bioper_outfile << speakerID << "," << probeID << "," << z << "," << d << std::endl;
    }

}

BiometricFile::~BiometricFile() {
    this->y_a_outfile.close();
    this->z_a_outfile.close();
    this->y_b_outfile.close();
    this->z_b_outfile.close();
    this->bioper_outfile.close();
}
