

#include <stdio.h>

#define Nb 4 

int Nr = 10; /* Number of round(Nr),
int Nb_k = 4;  /* Number of block of key, 

unsigned char in[16];          // plaintext block input array, 明文區塊輸入char陣列
unsigned char out[16];         // ciphertext block output array, 密文區塊輸出陣列
unsigned char state[4][4];     // temp state array in encrypt state, 加密運算過程中的的狀態陣列 4 * 4 
unsigned char Roundkey[176];   // round key array, stored Main Key and Expanded Key (Ex: AES-128(44words/176 bytes), AES-256(60w/260bytes)), 儲存主要鑰匙跟擴充鑰匙的陣列, w0(index 0 ~ 3) w1(index 4 ~ 7)....
unsigned char Key[16];         // Main key(input key Ex. AES-128(18 char), AES-256(32 char)), 輸入的金鑰

/* S-box */
int S_Box[256] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};

/* Inverse S-box */
int S_Box_Inv[256] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

/**
 * Rcon used in KeyExpansion
 * this Rcon table can gernerate from GF(2^8)
 * Rcon[0] will not be used(Easy to code), set any redundant num
 * AES uses up to rcon[10] for AES-128 (as 11 round keys are needed).
 */
int Rcon[11] = 
{
//   0     1     2     3      4    5     6     7     8    9     10
    0x87, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


/** Key Expansion function,
 *  Input: Key[], Nr(round), Nb, Nb_k(AES-128(4 block)
 *  Output: Roundkey[], 產生所有子鑰匙 - AES-128(44)
 */
void KeyExpansion(){
    unsigned char tempByte[4]; // store 4 temp Byte(1 word) when generate subkey
    unsigned char a0;       // temp - store byte when execute RotWord function
    
    
    for (int i = 0;i < Nb_k;i++){
        Roundkey[i * 4] = Key[i * 4];
        Roundkey[i *4 + 1] = Key[i * 4 + 1];
        Roundkey[i *4 + 2] = Key[i * 4 + 2];
        Roundkey[i *4 + 3] = Key[i * 4 + 3];
    }

    /**
     * Generate other subkey, 
     * Ex: AES-128: i= 4 ~ 43, 共 11  4block(128bit),  44 個word (W0 ~ W43).
     */
    for (int i = Nb_k;i < (Nb * (Nr + 1));i++)
    {
        for (int j = 0;j < 4;j++){ // block(W)
            tempByte[j] = Roundkey[(i - 1) * 4 + j]; // block(Word)tempW
        }
        if (i % Nb_k == 0){
            /**
             * Ex: AES-128 when generate W4, will use W3 do SubWord(RotWord(tempW)) XOR Rcon[4/4]
             *     AES-128 i Wi =  SubWord(RotWord(Wi-1)) XOR Rcon[i/4]
             */

            // RotWord function, [a0, a1, a2, a3](4byte) left circular shift in a word [a1, a2, a3, a0]
            a0 = tempByte[0];
            tempByte[0] = tempByte[1];
            tempByte[1] = tempByte[2];
            tempByte[2] = tempByte[3];
            tempByte[3] = a0;

            // SubWord function (S-Box substitution)
            tempByte[0] = S_Box[(int)tempByte[0]];
            tempByte[1] = S_Box[(int)tempByte[1]];
            tempByte[2] = S_Box[(int)tempByte[2]];
            tempByte[3] = S_Box[(int)tempByte[3]];
            
            // XOR Rcon[i/4], only leftmost byte are changed (只會XOR最左的byte)
            tempByte[0] = tempByte[0] ^ Rcon[i / Nb_k]; 
        }
        /**
         * Wn = Wn-1 XOR Wk    k = current word - Nb_k
         * Ex: AES-128   Nb_k = 4  when W5 = Wn-1(W4) XOR Wk(W1)
         * Ex: AES-256   Nb_k = 8  when W10 = Wn-1(W9) XOR Wk(W2) 
         */
        Roundkey[i * 4 + 0] = Roundkey[(i - Nb_k) * 4 + 0] ^ tempByte[0];
        Roundkey[i * 4 + 1] = Roundkey[(i - Nb_k) * 4 + 1] ^ tempByte[1];
        Roundkey[i * 4 + 2] = Roundkey[(i - Nb_k) * 4 + 2] ^ tempByte[2];
        Roundkey[i * 4 + 3] = Roundkey[(i - Nb_k) * 4 + 3] ^ tempByte[3];   
    }
}


// AddRoundKey
void AddRoundKey(int round)
{
    /**
     * first key index = round * 16 bytes = round * Nb * 4;
     * Nb = 4
     */
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= Roundkey[(i * Nb + j) + (round * Nb * 4)]; 
}


// Inverse S-Box Substitution
void SubBytes_Inv(){
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[i][j] = S_Box_Inv[state[i][j]];
}


// right(inverse) Circular Shift (row), 列移位函數
void ShiftRows_Inv(){
    unsigned char tempByte;
    
    // 2nd row right Circular Shift 1 byte
    tempByte    = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tempByte;

    // 3th row right Circular Shift 2 byte
    tempByte    = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tempByte;

    tempByte    = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tempByte;

    // 4th row right Circular Shift 3 byte
    tempByte    = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tempByte;
}


/* galois multiplication */
char AES_GMul(char a, char b)
{
    /* partial result, index, carry bit */
	char p = 0, i, c;
	
	/* for every bit... */
	for (i = 0; i < 8; i++) {
		if (b & 1) 
            p ^= a;
		/* detect if x^8 term is about to be generated */
		c = a & 0x80;  
		a <<= 1;
		/* replace x^8 with x^4 + x^3 + x + 1 */
		if (c) 
            a ^= 0x1B;
		b >>= 1;
	}
	
	/* return result */
	return p;
}
void MixColumns_Inv()
{
    int i, j, k;
	/* column storage */
	char s[4];
	/* matrix */
	char m[] = { 14, 11, 13,  9,
                     9, 14, 11, 13,
                    13,  9, 14, 11,
                    11, 13,  9, 14 };
    
	/* for every column */
	for (i = 0; i < 4; i++) {
        /* for every element in column */
        for (j = 0; j < 4; j++) {
            /* multiply and add */
            s[j]  = AES_GMul(state[0][i], m[j*4 + 0]);
            s[j] ^= AES_GMul(state[1][i], m[j*4 + 1]);
            s[j] ^= AES_GMul(state[2][i], m[j*4 + 2]);
            s[j] ^= AES_GMul(state[3][i], m[j*4 + 3]);
        }
		/* write back the result */
		state[0][i] = s[0]; state[1][i] = s[1];
		state[2][i] = s[2]; state[3][i] = s[3];
	}
}

/**
 *  Cihper_Inv  AES Decrypt function
 *  Inverse to Encrypt process
 */
void Cipher_Inv(){

    int round = Nr - 1;
    /**
     *  將in[](ciphertext) 轉換成 column 排列方式
     *  圖示:
     *  [b0 b1 ... b15] -> [b0 b4 b8  b12
     *                      b1 b5 b9  b13
     *                      b2 b6 b10 b14
     *                      b3 b7 b11 b15]
     */
    // for (int i = 0;i < 4;i++)
    //     for (int j = 0;j < 4;j++)
    //         state[j][i] = in[i * 4 + j]; // transform input, 將in[] 轉成 column形式(w0, w1, w2, w3)
    
    // round Nr : add round key, 
    AddRoundKey(Nr);

    // Round Nr-1 ~ 1, 反覆執行 1 ~ Nr-1回合
    for (round = Nr - 1;round > 0;round--){
        ShiftRows_Inv();
        SubBytes_Inv();
        AddRoundKey(round);
        MixColumns_Inv();
    }

    // Round Nr, no MixColumns(), 第 Nr 回合 沒有混合行運算
    ShiftRows_Inv();
    SubBytes_Inv();
    AddRoundKey(0);

    /**
     *  將state[] transform 到 out[]上
     *  圖示:
     *   [b0 b4 b8  b12
     *    b1 b5 b9  b13    --> [b0 b1 b2 ... b15]
     *    b2 b6 b10 b14
     *    b3 b7 b11 b15]
     */
    for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            out[i * 4 + j]=state[j][i];
}


int main(){
    
    unsigned char input_key[17];
    printf("Enter AES KEY (16 characters) : ");
        // scanf("%s", input_key);
    gets(input_key);
    for (int i = 0;i < 16;i++)
        Key[i] = input_key[i];
    printf("\n");

    KeyExpansion();
    unsigned char input_text[16]={0x29,0xC3,0x50,0x5F,0x57,0x14,0x20,0xF6,0x40,0x22,0x99,0xB3,0x1A,0x02,0xD7,0x3A};
    // printf("Enter ciphertext (16 characters) : ");
    // scanf("%s", &input_plaintext);
    // gets(input_text);
    
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] = input_text[i * 4 + j];
    
    Cipher_Inv(); 
    printf("\n");
    printf("Plaintext for given Ciphertext \t");
    for(int i=0;i<16;i++){
        printf("%02x ",out[i]);
    }
}
