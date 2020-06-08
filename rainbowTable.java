/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cryptographypractical;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
// Import the HashMap class
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 *
 * @author jordandraper
 */
public class rainbowTable {

    //The chain length 
    static int chainLength = 5000;
    //Edit how many pairs of chains you want for the hashtable
    static int numberOfChains = 90000;
    //Set the maximum length that the strings can reach  
    static int maxStringLength = 8;
    //Both SALTCHARS and alphabet must have the SAME set for this to work
    //static String SALTCHARS = "abcdefghijklmnopqrstuvwxyz1234567890";
    static String SALTCHARS = "0123456789";
    //static String[] alphabet = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
    static String[] alphabet = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
    static int chainPairs = 42000; //Set it equal to number of hash map pairs after loading table, this will control how long it searches for.

//Here we set the location to store the hashmap - feel free to just set it to /downloads
    static String hashMapFileLocation = "/Users/jordandraper/Desktop/Files/University/Year 3/ESD/cryptographyPractical/src/cryptographypractical/output.ser";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, UnsupportedEncodingException, IOException {
        /////////////////////////////////////////
        //Comment out the generation if generated
        //
        //generateRainbowTable(); //Generate the table - comment out if already generated 
        //BUILD SUCCESSFUL (total time: 40 minutes 36 seconds) at 90000 size with 60k colissions.
        //
        //Comment out the generation if generated
        //////////////////////////////////////////

        //Load the hash table 
        HashMap<String, String> wordChain = loadHashMapFile(); //Load hashmap from the file
        //System.out.println(Arrays.asList(wordChain)); //Testing purposes
        System.out.println("Hash map pairs: " + wordChain.size()); //Print size
        System.out.println("Attempting to crack passwords... ");

        //
        //Cracking passwords below
        //
        //Input hashes of 10 random hashes from module leader email here
        crackPasswordRefined("fe635ae88967693bc7e7eead87906e62e472c52f",wordChain); //187494
        crackPasswordRefined("3ac2d907663deccd843f9bbcf0c63bd3ad885a0e",wordChain); //940376
        crackPasswordRefined("3557c095ed6c16a90febda48d6b3a4490107b0d9",wordChain); //Can't find
        crackPasswordRefined("85e04129ed328d4a2b3eedabca74d08b3e6badc1",wordChain); //0987593
        crackPasswordRefined("70352f41061eda4ff3c322094af068ba70c3b38b",wordChain); //00000000
        crackPasswordRefined("052bd5b02559d1270866c5626538e720cec0c135",wordChain); //93020840
        crackPasswordRefined("3e71f65d56cb29521ac16ff1f92ecace156b1db5",wordChain); //Can't find
        crackPasswordRefined("bfc52d4e36cb45cb667749982755e63630f3bc93",wordChain); //87657890
        crackPasswordRefined("8cb2237d0679ca88db6464eac60da96345513964",wordChain); //12345
        crackPasswordRefined("38bbc0a1ca7e9b3e9f6ab33782e0f780f009db1f",wordChain); //99887766
        //crackPassword("", wordChain); //
        System.out.println("Cracking complete.");

        
        //
    }

    private static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buf.append((char) ('0' + halfbyte));
                } else {
                    buf.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    public static String SHA1(String text)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md;
        md = MessageDigest.getInstance("SHA-1");
        byte[] sha1hash = new byte[40];
        md.update(text.getBytes("iso-8859-1"), 0, text.length());
        sha1hash = md.digest();
        return convertToHex(sha1hash);
    }

    public static String reduce1(String s, int reduceNumber) {
        int primeNumber = 214722973; //p > sizeOfPasswordSpace 
        //This prime number is too small - causing collisions
        int AsciiSum = 0;
        //Go through each char of the hash
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            int asciiCode = ch;
            // type casting char as int
            int asciiValue = (int) ch;
            //SUM the ascii of each char and put to power of 2^i... Adding "reduceNumber" to track chain position
            asciiValue = (int) (asciiValue * Math.pow(2, i)) + reduceNumber;
            asciiValue = asciiValue % primeNumber;

            AsciiSum = AsciiSum + asciiValue;

        }
        //get int n
        int n = (AsciiSum % primeNumber);

        //System.out.println("The Ascii sum is: " + AsciiSum);
        //System.out.println("n is equal to " + n);
        //Turn back to string for next plaintext
        return int_to_string(n);
    }

    public static String int_to_string(int n) {
        /* return an empty string if n <0 */
        int base = alphabet.length;
        int r;
        String s = "";
        while (n >= 0) {
            r = n % base;
            n = n / base;
            /* shift to right one digit (position) */
            s = alphabet[r] + s;
            n = n - 1;
            /*  this line is special! need it if we want handle 
			    different length of the strings */
        }
        //System.out.println("S is returned as: " + s);
        return s;
    }

    public static void generateRainbowTable() throws FileNotFoundException, NoSuchAlgorithmException, IOException {
        System.out.println("Generating the table, please wait");
        //Declare the hashmap
        HashMap<String, String> wordChain = new HashMap<String, String>();
        FileOutputStream fileOut = new FileOutputStream(hashMapFileLocation);
        ObjectOutputStream out = new ObjectOutputStream(fileOut);
        int hashMapCollisions = 0;
        //Will cycle this loop for however many chains we want to create
        for (int z = 0; z < numberOfChains; z++) {
            //Creating random string for start of chain e.g. the 0th position
            int maximumLength = new Random().nextInt(maxStringLength + 1);
            String pwd = getSaltString(maximumLength);
            String firstWord = pwd;
            //System.out.println("firstWord is: " + firstWord);
            //First word is a plain text, need to reduce it to the first actual chained plaintext
            for (int x = 1; x <= chainLength; x++) {
                //Cycle chainLength to create chain
                String hashLine = SHA1(pwd); //Hashes line from dictionary
                pwd = reduce1(hashLine, x); //Applies reduce function to create a number  
                //System.out.println(pwd + " : ...X is: " + x);
            }
            String lastWord = pwd; //Last word in this chain e.g. chain 4999
            //Check if there is colission
            if (wordChain.containsKey(lastWord) || wordChain.containsValue(firstWord)) {
                System.out.println("Collision detected");
                firstWord = "";
                lastWord = "";
                hashMapCollisions++;
            } else {
                //Put lastWord firstWord into hashmap
                wordChain.put(lastWord, firstWord);
            }
        }
        //Close file and give user feedback that it is complete
        System.out.println("Hash map pairs: " + wordChain.size()); //Print size
        System.out.println("Hash map collisions: " + hashMapCollisions);
        System.out.println(Arrays.asList(wordChain));
        out.writeObject(wordChain);
        out.close();
        fileOut.close();
        System.out.println("Finished generating rainbow table.");
        System.out.println("Serialized data saved in file");
    }

    //Function to load hashmap to be used that we previously created
    public static HashMap<String, String> loadHashMapFile() {
        HashMap<String, String> wordChain = new HashMap<String, String>();

        try {
            FileInputStream fileIn = new FileInputStream(hashMapFileLocation);
            ObjectInputStream in = new ObjectInputStream(fileIn);
            wordChain = (HashMap) in.readObject();
            in.close();
            fileIn.close();
            return wordChain;
        } catch (IOException i) {
        } catch (ClassNotFoundException c) {
            System.out.println("File not found... Generate rainbow table first");
        }
        return null;
    }

    //Used to create random string at start of rainbow table chain
    public static String getSaltString(int len) {
        //SALTCHARS is used here - can be edited at top of file.
        StringBuilder salt = new StringBuilder();
        Random rnd = new Random();
        while (salt.length() < len) { // length of the random string.
            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
            salt.append(SALTCHARS.charAt(index));
        }
        String saltStr = salt.toString();
        return saltStr;

    }

    public static void crackPasswordRefined(String hashedPassword, HashMap wordChain) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        int pos = chainLength;
        while (pos > 0) {
            //1 apply reduce function
            String pwd = chainReduce(hashedPassword, pos);
            //Need to find correct pwd which is not working currently
            //System.out.println("pwd : " + pwd);

            //Check if pwd in key of hashmap
            if (wordChain.containsKey(pwd)) {
               // System.out.println("POS: "+ pos);
                //System.out.println("TRUE " + pwd);
                //go to the beginning of the chain, follow the chain to get the password
                String startChain = (String) wordChain.get(pwd);
               // System.out.println("Password is in the chain which starts " + startChain);          
                //startChain is the random int... Need to reduce it starting from 1 up until pwd-1 to get value
                pwd = startChain;               
                for (int x = 1; x < pos+1; x++) {
                //Cycle chainLength to create chain
                String hashLine = SHA1(pwd); //Hashes line from dictionary   
                //Check if the hashes match if so we found the initial hashed value
                if(hashLine.equals(hashedPassword)){
                    System.out.println("Solution found: " + pwd);
                    return;
                    //Exit this function - solved it
                }
                pwd = reduce1(hashLine, x); //Applies reduce function to create a number  
                }           
            }
            pos--;
        }
        //Feedback to user pwd was not in our pwd space
        System.out.println("Could not find pwd");
    }

    public static String chainReduce(String hash, int pos) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String pwd = reduce1(hash, pos);
        //Cycle through the chain geting the pwd pos
        while (pos != chainLength) {
            pos++;
            hash = SHA1(pwd);
            pwd = reduce1(hash, pos);  // R at pos
        }
        return pwd;
    }
}
