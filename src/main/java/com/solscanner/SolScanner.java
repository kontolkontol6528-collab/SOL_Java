package com.solscanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class SolScanner {
    private static final Path BIP39_FILE = Path.of("bip39.txt");
    private static final Path HITS_FILE = Path.of("hits.txt");
    private static final String RPC_URL = "https://solana-rpc.publicnode.com";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final List<String> wordlist;
    private final Map<String, Integer> wordIndex;

    private final AtomicLong tries = new AtomicLong();
    private final AtomicLong hits = new AtomicLong();

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public SolScanner(List<String> wordlist) {
        this.wordlist = List.copyOf(wordlist);
        this.wordIndex = createIndex(this.wordlist);
    }

    private static Map<String, Integer> createIndex(List<String> words) {
        return Collections.unmodifiableMap(
                words.stream().collect(Collectors.toMap(w -> w, words::indexOf))
        );
    }

    public static void main(String[] args) throws Exception {
        List<String> words = readBip39File(BIP39_FILE);
        if (words.size() != 2048) {
            System.err.println("Warning: bip39 wordlist size is not 2048 (found " + words.size() + "). Proceeding anyway.");
        }

        SolScanner scanner = new SolScanner(words);

        int workers = Math.max(1, Runtime.getRuntime().availableProcessors() - 1);
        ExecutorService pool = Executors.newFixedThreadPool(workers);

        for (int i = 0; i < workers; i++) {
            pool.submit(() -> {
                try {
                    scanner.workerLoop();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }

        ScheduledExecutorService status = Executors.newSingleThreadScheduledExecutor();
        status.scheduleAtFixedRate(() -> {
            System.out.print("\rTries : " + scanner.tries.get() + "  Hits : " + scanner.hits.get());
            System.out.flush();
        }, 0, 1, TimeUnit.SECONDS);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println();
            System.out.println("Shutting down...");
            pool.shutdownNow();
            status.shutdownNow();
        }));

        Thread.currentThread().join();
    }

    private static List<String> readBip39File(Path path) throws IOException {
        if (Files.exists(path)) {
            return Files.readAllLines(path, StandardCharsets.UTF_8).stream()
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
        }
        InputStream is = SolScanner.class.getClassLoader().getResourceAsStream("bip39.txt");
        if (is != null) {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                List<String> out = new ArrayList<>();
                String line;
                while ((line = br.readLine()) != null) {
                    String s = line.trim();
                    if (!s.isEmpty()) out.add(s);
                }
                return out;
            }
        }
        throw new IOException("bip39.txt not found in working directory or classpath.");
    }

    private void workerLoop() throws Exception {
        List<String> localWords = new ArrayList<>(wordlist);
        while (true) {
            Collections.shuffle(localWords);
            List<String> candidate = new ArrayList<>(localWords.subList(0, 12));
            tries.incrementAndGet();
            if (!isValidBip39(candidate)) continue;

            String mnemonic = String.join(" ", candidate);
            try {
                byte[] seed = mnemonicToSeed(mnemonic, "");

                // Derive using SLIP-0010 + ed25519 (Phantom-compatible)
                byte[] derivedPrivSeed = derivePrivateKeyFromSeed(seed, "m/44'/501'/0'/0'");
                byte[] pubKey = ed25519PublicFromPrivateSeed(derivedPrivSeed);
                String address = Base58.encode(pubKey);

                long lamports = getBalance(address);
                double sol = lamports / 1_000_000_000.0;
                if (lamports > 0) {
                    hits.incrementAndGet();
                    appendHit(mnemonic, address, String.valueOf(sol) + "SOL (" + lamports + " lamports)");
                } else {
                    // no balance
                }
            } catch (Exception e) {
                System.err.println("Error during derivation/check for mnemonic: " + mnemonicSnippet(candidate));
                e.printStackTrace();
            }
        }
    }

    private String mnemonicSnippet(List<String> candidate) {
        try {
            return String.join(" ", candidate.subList(0, Math.min(12, candidate.size())));
        } catch (Exception e) {
            return "<mnemonic unavailable>";
        }
    }

    private boolean isValidBip39(List<String> mnemonicWords) throws Exception {
        int n = mnemonicWords.size();
        if (n % 3 != 0) return false;

        int bits = n * 11;
        int checksumLength = bits / 33;
        int entropyLength = bits - checksumLength;

        StringBuilder bitsBuilder = new StringBuilder();
        for (String w : mnemonicWords) {
            Integer idx = wordIndex.get(w);
            if (idx == null) return false;
            String b = String.format("%11s", Integer.toBinaryString(idx)).replace(' ', '0');
            bitsBuilder.append(b);
        }
        String allBits = bitsBuilder.toString();
        String entropyBits = allBits.substring(0, entropyLength);
        String checksumBits = allBits.substring(entropyLength);

        byte[] entropy = new byte[entropyLength / 8];
        for (int i = 0; i < entropy.length; i++) {
            int from = i * 8;
            String byteStr = entropyBits.substring(from, from + 8);
            entropy[i] = (byte) Integer.parseInt(byteStr, 2);
        }

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(entropy);
        String hashBits = toBitString(hash);
        String expectedChecksum = hashBits.substring(0, checksumLength);

        return expectedChecksum.equals(checksumBits);
    }

    private static String toBitString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }

    private static byte[] mnemonicToSeed(String mnemonic, String passphrase) throws Exception {
        String salt = "mnemonic" + (passphrase == null ? "" : passphrase);
        PBEKeySpec spec = new PBEKeySpec(mnemonic.toCharArray(), salt.getBytes(StandardCharsets.UTF_8), 2048, 512);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        return skf.generateSecret(spec).getEncoded();
    }

    // ---------- SLIP-0010 / Ed25519 helpers ----------

    private static byte[] hmacSha512(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(new SecretKeySpec(key, "HmacSHA512"));
        return mac.doFinal(data);
    }

    /**
     * Derive a 32-byte Ed25519 private key seed using SLIP-0010 with key "ed25519 seed".
     * The method treats path indices as hardened (sets the hardened bit).
     */
    private static byte[] derivePrivateKeyFromSeed(byte[] seed, String path) throws GeneralSecurityException {
        byte[] I = hmacSha512("ed25519 seed".getBytes(StandardCharsets.UTF_8), seed);
        byte[] key = Arrays.copyOfRange(I, 0, 32);
        byte[] chainCode = Arrays.copyOfRange(I, 32, 64);

        String[] parts = path.split("/");
        for (int i = 1; i < parts.length; i++) {
            String p = parts[i];
            String numberStr = p.endsWith("'") ? p.substring(0, p.length() - 1) : p;
            int idx = Integer.parseInt(numberStr);
            int childIndex = idx | 0x80000000;

            ByteBuffer data = ByteBuffer.allocate(1 + 32 + 4);
            data.put((byte) 0x00);
            data.put(key);
            data.putInt(childIndex);

            I = hmacSha512(chainCode, data.array());
            key = Arrays.copyOfRange(I, 0, 32);
            chainCode = Arrays.copyOfRange(I, 32, 64);
        }
        return key;
    }

    private static byte[] ed25519PublicFromPrivateSeed(byte[] privSeed) {
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(privSeed, 0);
        Ed25519PublicKeyParameters pub = priv.generatePublicKey();
        return pub.getEncoded();
    }

    // ---------- RPC with retry/backoff (kept from previous impl) ----------

    private long getBalance(String address) {
        final int maxRetries = 5;
        final long baseDelayMs = 500L;

        String req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"" + address + "\"]}";

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(RPC_URL))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(req))
                    .build();
            try {
                HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                int status = resp.statusCode();
                if (status != 200) {
                    String body = resp.body();
                    System.err.println("RPC error for address " + address + ": HTTP " + status + " - response: " + body);
                    if ((status >= 500 && status < 600) || status == 429) {
                        backoffSleep(attempt, baseDelayMs);
                        continue;
                    }
                    return 0L;
                }

                JsonNode root = MAPPER.readTree(resp.body());
                if (root.has("error")) {
                    String err = root.get("error").toString();
                    System.err.println("RPC returned error for address " + address + ": " + err);
                    if (err.toLowerCase().contains("rate") || err.toLowerCase().contains("limit") || err.toLowerCase().contains("timeout")) {
                        backoffSleep(attempt, baseDelayMs);
                        continue;
                    }
                    return 0L;
                }
                if (root.has("result") && root.get("result").has("value")) {
                    return root.get("result").get("value").asLong();
                } else {
                    System.err.println("Unexpected RPC response for address " + address + ": " + resp.body());
                    backoffSleep(attempt, baseDelayMs);
                    continue;
                }
            } catch (IOException e) {
                System.err.println("IO error when querying balance for " + address + " (attempt " + attempt + "): " + e.getMessage());
                if (attempt == maxRetries) {
                    return 0L;
                }
                backoffSleep(attempt, baseDelayMs);
            } catch (InterruptedException e) {
                System.err.println("Interrupted when querying balance for " + address + ": " + e.getMessage());
                Thread.currentThread().interrupt();
                return 0L;
            } catch (Exception e) {
                System.err.println("Unexpected error when querying balance for " + address + " (attempt " + attempt + "): " + e.getMessage());
                e.printStackTrace();
                if (attempt == maxRetries) return 0L;
                backoffSleep(attempt, baseDelayMs);
            }
        }
        System.err.println("Failed to get balance for " + address + " after " + maxRetries + " attempts.");
        return 0L;
    }

    private void backoffSleep(int attempt, long baseDelayMs) {
        long delay = baseDelayMs * (1L << (attempt - 1));
        long jitter = ThreadLocalRandom.current().nextLong(100, 301);
        long sleepMs = delay + jitter;
        try {
            Thread.sleep(sleepMs);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private synchronized void appendHit(String mnemonic, String address, String balance) {
        StringBuilder sb = new StringBuilder();
        sb.append(mnemonic).append(System.lineSeparator());
        sb.append(address).append(System.lineSeparator());
        sb.append(balance).append(System.lineSeparator());
        try {
            Files.writeString(HITS_FILE, sb.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Failed to append hit to " + HITS_FILE + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
}
