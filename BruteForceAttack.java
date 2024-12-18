import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BruteForceAttack {

    public static void main(String[] args) {
        // Target hash (SHA-256 in this example) to compare against
        String targetHash = "bd3740f49dfed866992404ea130ea510a6103a4038ef7970dec0f9d771e0ad31"; // Hash of "panis"

        // Path to the dictionary file
        String dictionaryFile = "dictionary.txt";

        try {
            boolean found = performDictionaryAttack(dictionaryFile, targetHash);
            if (!found) {
                System.out.println("Match not found in the dictionary!");
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            System.err.println("An error occurred: " + e.getMessage());
        }
    }

    public static boolean performDictionaryAttack(String dictionaryFile, String targetHash)
            throws IOException, NoSuchAlgorithmException {

        try (BufferedReader reader = new BufferedReader(new FileReader(dictionaryFile))) {
            String match;

            while ((match = reader.readLine()) != null) {
                String hashedMatch = hashMatch(match);

                if (hashedMatch.equals(targetHash)) {
                    System.out.println("Match found: " + match);
                    return true;
                }
            }
        }

        return false;
    }

    public static String hashMatch(String match) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(match.getBytes());

        // Convert byte array to hexadecimal format
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }
}

