package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Maps;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A class to hash a batch of passwords in a separate thread.
 * Add implements Runnable interface rather than extends Thread
 * Allows this class to be run on separate threads --> CONCURRENCY!
 */
public class BatchPasswordHasher implements Runnable {

    // Note: 'final' attribute is used on member data to make it immutable as required for concurrency.
    //              'concurrency' simply means multiple instances of the same process running on separate threads at the same time.
    // We want 4 instances of BatchPasswordHasher to break up 100 passwords into 4 lists of 25 passwords
    private final List<String> passwords;   // passwords to be hashed - parameter to the ctor
    private final Map<String, String> passwordToHashes; // contains the hashed passwords
    private final String salt;  // salt value to be used in hashing the passwords

    // ctor receive a List of passwords and a salt
    public BatchPasswordHasher(List<String> passwords, String salt) {
        // replace this code with a defensive copy for concurrency and immutability purposes
        //this.passwords = passwords;
        this.passwords = new ArrayList<>(passwords);    // new code - defensive copy of passwords List.
        this.salt = salt;
        passwordToHashes = new HashMap<>();
    }

    /**
     *  Hashes all of the passwords, and stores the hashes in the passwordToHashes Map.
     *  This method will be called from run()
     */
    public void hashPasswords() {
        try {
            for (String password : passwords) {
                final String hash = PasswordUtil.hash(password, salt);
                passwordToHashes.put(password, hash);
            }
            System.out.println(String.format("Completed hashing batch of %d passwords.", passwords.size()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Returns a map where the key is a plain text password and the key is the hashed version of the plaintext password
     * and the class' salt value.
     *
     * @return passwordToHashes - a map of passwords to their hash value.
     */
    public Map<String, String> getPasswordToHashes() {
        return passwordToHashes;
    }


    // run() is required by the Runnable Interface
    //      run() is automatically called when the thread assigned to this class is started.
    //          like main() for a Java app, or handleRequest for an AWS Lambda function.
    @Override
    public void run() {
        hashPasswords(); // call the method in this class to hash the passwords
    }
}
