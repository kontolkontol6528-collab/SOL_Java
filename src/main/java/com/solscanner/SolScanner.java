package com.solscanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.p2p.solanaj.crypto.DerivationPath;
import org.p2p.solanaj.crypto.KeyPair;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
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

        // keep main alive
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println();
            System.out.println("Shutting down...");
            pool.shutdownNow();
            status.shutdownNow();
        }));

        // block forever
        Thread.currentThread().join();
    }

    private static List<String> readBip39File(Path path) throws IOException {
        if (Files.exists(path)) {
            return Files.readAllLines(path, StandardCharsets.UTF_8).stream()
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
        }
        // try resource
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

            // valid mnemonic -> derive Solana address
            String mnemonic = String.join(" ", candidate);
            try {
                byte[] seed = mnemonicToSeed(mnemonic, "");

                // Derive using solanaj DerivationPath
                // Using path exactly: m/44'/501'/0'/0
                KeyPair kp = DerivationPath.deriveEd25519KeyPair(seed, "m/44'/501'/0'/0");
                String address = kp.getPublicKey().toBase58();

                long lamports = getBalance(address);
                double sol = lamports / 1_000_000_000.0;
                if (lamports > 0) {
                    hits.incrementAndGet();
                    appendHit(mnemonic, address, String.valueOf(sol) + "SOL (" + lamports + " lamports)");
                } else {
                    // User requested to append even tiny balances like 0.0001 but says append even if 0.0001; but we only append non-zero per instruction.
                    // We'll append non-zero only. If you want to append zeros too, change condition.
                }
            } catch (Exception e) {
                // ignore derivation errors, continue
                e.printStackTrace();
            }
        }
    }

    private boolean isValidBip39(List<String> mnemonicWords) throws Exception {
        int n = mnemonicWords.size();
        if (n % 3 != 0) return false; // BIP39 word count must be multiple of 3 (12,15,18,21,24)

        int bits = n * 11;
        int checksumLength = bits / 33; // entropy/32, entropy = bits - checksum
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
        byte[] key = skf.generateSecret(spec).getEncoded();
        return key;
    }

    private long getBalance(String address) throws Exception {
        String req = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"" + address + "\"]}";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(RPC_URL))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(req))
                .build();
        HttpResponse<String> resp = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) return 0L;
        JsonNode root = MAPPER.readTree(resp.body());
        if (root.has("result") && root.get("result").has("value")) {
            return root.get("result").get("value").asLong();
        }
        return 0L;
    }

    private synchronized void appendHit(String mnemonic, String address, String balance) {
        StringBuilder sb = new StringBuilder();
        sb.append(mnemonic).append(System.lineSeparator());
        sb.append(address).append(System.lineSeparator());
        sb.append(balance).append(System.lineSeparator());
        try {
            Files.writeString(HITS_FILE, sb.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
