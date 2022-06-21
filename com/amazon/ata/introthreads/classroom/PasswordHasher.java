package com.amazon.ata.introthreads.classroom;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.prefs.BackingStoreException;

/**
 * A class to pre-compute hashes for all common passwords to speed up cracking the hacked database.
 *
 * Passwords are downloaded from https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials
 */
public class PasswordHasher {
    // should create the file in your workspace directory
    private static final String PASSWORDS_AND_HASHES_FILE = "./passwordsAndHashesOutput.csv";
    private static final String DISCOVERED_SALT = "salt";   // value used to hash passwords
                                                            // the salt is not a commonly used word
                                                            // salts are usually a random set of characters

    /**
     * Generates hashes for all of the given passwords.
     *
     * @param passwords List of passwords to hash
     * @return map of password to hash
     * @throws InterruptedException
     */
    public static Map<String, String> generateAllHashes(List<String> passwords) throws InterruptedException {
        // Map returned with the passwords and salt
        // add 'final' to make immutable for concurrency
        // Note the use of the new concurrent Map instead of the Java map
        final Map<String, String> passwordToHashes = Maps.newConcurrentMap(); // this is a thread-safe Map

        // Split the passwords list into 4 sublists:
        // partition returns a List of Lists
        //                                              original-list,      number of elements in each subList
        List<List<String>> passwordsubLists = Lists.partition(passwords, passwords.size()/4);

        // Due to the BatchPasswordHasher being removed from memory when the thread completes,
        //      AND we need the hashed passwords from the BatchPasswordHasher when its done
        //      we need to store the BatchPasswordHasher so it is not removed from memory when the thread is done.
        //   SO, we need to Create a List of BatchPasswordHasher to hold the data:
        List<BatchPasswordHasher> theBatchHashers = new ArrayList<>(); //*****

        // Since we don't know how long a thread will run, we need to WAIT for it to complete
        //      before we can copy the hashed passwords out of the BatchPWHasher assigned to the thread.
        // We have a method called waitForThreadsToComplete() which receieves a List of Threads you want to wait for completion
        List<Thread> theThreads = new ArrayList<>();    // Hold the Threads in a List that we want waitForThreadsToCOmplete() to wait on

//     Replace the single call to the BatchPasswordHasher with one for each sublist on a thread:
//        BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwords, DISCOVERED_SALT);
//        batchHasher.hashPasswords();
//        passwordToHashes.putAll(batchHasher.getPasswordToHashes());

        // Logic: loop through the List of Sublist and start a thread for each sublist with a BatchPasswordHasher
        for (int i = 0; i < passwordsubLists.size(); i++) {
            //  we have to get the sublist
            BatchPasswordHasher batchHasher = new BatchPasswordHasher(passwordsubLists.get(i), DISCOVERED_SALT);
            theBatchHashers.add(batchHasher);  // ---> ***** Remember this instance of BatchPasswordHasher so we can get
                                                // hashed passwords out of it when it is done.
            // Set up a new Thread:
            Thread aThread = new Thread(batchHasher); // --> replaces the batchHasher.hashPasswords(); call in the commented-out code above
            theThreads.add(aThread);    // add a new Thread to the List of Threads we want to wait on.
            aThread.start(); // start() creates a separate thread and then Automatically calls run() method on the class assigned to the Thread
        }
        // now that all of the Threads are created and started, we have to wait for them to all finish
        //      before we copy their hashed passwords to our returned Map
        waitForThreadsToComplete(theThreads);

        // Now that all threads have completed and each BatchPWHasher for the thread has their hashed pw
        //      we need to copy their hashed passwords to our returned Map
        // Loop through the List of BatchPWHasher and copy their hashed pw
        for (BatchPasswordHasher aBatchPasswordHasher : theBatchHashers) {
            passwordToHashes.putAll(aBatchPasswordHasher.getPasswordToHashes());
        }
        return passwordToHashes;
    }

    /**
     * Makes the thread calling this method wait until passed in threads are done executing before proceeding.
     * Given a list of Threads, this method will not return until all Threads in the List have completed.
     * @param threads to wait on
     * @throws InterruptedException
     */
    public static void waitForThreadsToComplete(List<Thread> threads) throws InterruptedException {
        for (Thread thread : threads) {     // Loop through the List of Threads given and wait until they are all done.
            thread.join();                  // .join() will WAIT for a thread to complete. Don't be fooled by the name 'join'
        }
    }

    /**
     * Writes pairs of password and its hash to a file.
     */
    static void writePasswordsAndHashes(Map<String, String> passwordToHashes) {
        File file = new File(PASSWORDS_AND_HASHES_FILE);
        try (
            BufferedWriter writer = Files.newBufferedWriter(file.toPath());
            CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT)
        ) {
            for (Map.Entry<String, String> passwordToHash : passwordToHashes.entrySet()) {
                final String password = passwordToHash.getKey();
                final String hash = passwordToHash.getValue();

                csvPrinter.printRecord(password, hash);
            }
            System.out.println("Wrote output of batch hashing to " + file.getAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
