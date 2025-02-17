#include <iostream>
#include <helib/helib.h>
#include <helib/EncryptedArray.h>
#include <helib/Context.h>
#include <helib/FHE.h>
#include <helib/Ctxt.h>
#include <fstream>
#include <vector>
#include <cmath>

using namespace std;
using namespace helib;

// MNIST constants
const string training_image_fn = "mnist/train-images.idx3-ubyte";
const string training_label_fn = "mnist/train-labels.idx1-ubyte";
const int nTraining = 60000;
const int width = 28;
const int height = 28;

// CKKS parameters
const long m = 4096;      // Specific modulus
const long p = 2;         // Plaintext base
const long r = 1;         // Number of primes in the modulus chain
const long L = 50;        // Number of levels in the modulus chain
const long c = 3;         // Number of columns in key switching matrix
const long w = 64;        // Hamming weight of secret key
const long d = 0;         // Degree of the field extension (use 0 for large rings)

// Neural network parameters
const int n1 = width * height;  // Number of input neurons
const int n2 = 128;             // Number of hidden neurons
const int n3 = 10;              // Number of output neurons
const int epochs = 512;
const double learning_rate = 1e-3;
const double momentum = 0.9;
const double epsilon = 1e-3;

// MNIST image and label data
vector<vector<int>> mnistImages(nTraining, vector<int>(n1 + 1, 0));
vector<int> mnistLabels(nTraining, 0);

// Setup HElib context
Context context(m, p, r);
buildModChain(context, L, c);

// Generate a secret key
SecKey secretKey(context);
secretKey.GenSecKey(w);

// Compute key-switching matrices that we need
addSome1DMatrices(secretKey);

// Set up the public key for encryption
const PubKey& publicKey = secretKey;

// Function to load MNIST images
void loadMNISTImages() {
    ifstream image(training_image_fn, ios::in | ios::binary);
    if (!image.is_open()) {
        cerr << "Error opening MNIST image file." << endl;
        exit(1);
    }

    // Read the MNIST image header
    char number;
    for (int i = 0; i < 16; ++i) {
        image.read(&number, sizeof(char));
    }

    // Read each image
    for (int idx = 0; idx < nTraining; ++idx) {
        for (int j = 0; j < height; ++j) {
            for (int i = 0; i < width; ++i) {
                image.read(&number, sizeof(char));
                mnistImages[idx][i + j * width + 1] = (number == 0) ? 0 : 1;
            }
        }
    }

    image.close();
}

// Function to load MNIST labels
void loadMNISTLabels() {
    ifstream label(training_label_fn, ios::in | ios::binary);
    if (!label.is_open()) {
        cerr << "Error opening MNIST label file." << endl;
        exit(1);
    }

    // Read the MNIST label header
    char number;
    for (int i = 0; i < 8; ++i) {
        label.read(&number, sizeof(char));
    }

    // Read each label
    for (int idx = 0; idx < nTraining; ++idx) {
        label.read(&number, sizeof(char));
        mnistLabels[idx] = number;
    }

    label.close();
}

// Encrypt MNIST images using CKKS
vector<Ctxt> encryptMNISTImages(const vector<vector<int>>& images, const PubKey& publicKey) {
    vector<Ctxt> encryptedImages;

    EncryptedArray ea(context);
    PlaintextArray ptxtSlots(ea);
    Ctxt ctxt(publicKey);

    for (const auto& image : images) {
        // Set plaintext values to image pixels
        for (size_t i = 0; i < image.size(); ++i) {
            ptxtSlots[i] = image[i];
        }

        // Encrypt plaintext to ciphertext
        ea.encrypt(ctxt, publicKey, ptxtSlots);
        encryptedImages.push_back(ctxt);
    }

    return encryptedImages;
}

// Encrypt MNIST labels using CKKS
vector<Ctxt> encryptMNISTLabels(const vector<int>& labels, const PubKey& publicKey) {
    vector<Ctxt> encryptedLabels;

    EncryptedArray ea(context);
    PlaintextArray ptxtSlots(ea);
    Ctxt ctxt(publicKey);

    for (const auto& label : labels) {
        ptxtSlots[0] = label;
        ea.encrypt(ctxt, publicKey, ptxtSlots);
        encryptedLabels.push_back(ctxt);
    }

    return encryptedLabels;
}

int main() {
    // Load MNIST images
    loadMNISTImages();

    // Encrypt MNIST images and labels using CKKS
    vector<Ctxt> encryptedImages = encryptMNISTImages(mnistImages, publicKey);
    vector<Ctxt> encryptedLabels; // Encrypt labels if needed

    // Initialize encrypted weights (to be initialized appropriately)
    vector<Ctxt> encryptedWeights1(n1 * n2 + 1, Ctxt(publicKey));
    vector<Ctxt> encryptedWeights2(n2 * n3 + 1, Ctxt(publicKey));
}
