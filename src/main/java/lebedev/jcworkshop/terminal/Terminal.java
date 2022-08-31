package lebedev.jcworkshop.terminal;

import javax.smartcardio.*;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;


public class Terminal {

    private static final byte PUBLIC_INS = (byte) 0x01;
    private static final byte AUTH_INS = (byte) 0x02;
    private static final byte WITHDRAW_INS = (byte) 0x03;
    private static final byte NAME_INS = (byte) 0x04;

    private static final short WITHDRAW_AMOUNT = 777;

    private static final String ALLOWED_MOD = "9996899334933189437697148695631193831443441978764907313499593524610806532779272386204529079515953309771891043185633992806224750893564220475896386704098191";
    private static final String ALLOWED_EXP = "65537";
    private static final Logger LOGGER = Logger.getLogger(Terminal.class.toString());
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static ArrayList<String> scoreboard = new ArrayList<String>();

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static void logCmd(CommandAPDU cmd) {
        LOGGER.info(">>> " + bytesToHex(cmd.getBytes()));
    }

    private static void logAns(ResponseAPDU resp) {
        LOGGER.info("<<< " + bytesToHex(resp.getBytes()));
    }

    // команда получения публичного ключа с карты
    private static RSAPublicKey getPublicKey(CardChannel cc) throws CardException, NoSuchAlgorithmException, InvalidKeySpecException {
        final CommandAPDU cmd = new CommandAPDU(0x00, PUBLIC_INS, 0, 0, 1);
        logCmd(cmd);
        final ResponseAPDU responseAPDU = cc.transmit(cmd);
        logAns(responseAPDU);
        if (responseAPDU.getSW() != 0x9000) {
            throw new RuntimeException();
        }

        // формат buf:
        // short expLen;
        // byte[expLen] exp;
        // short modLen;
        // byte[modLen] mod;

        byte[] buf = responseAPDU.getBytes();
        int expLen = (buf[0] << 8) | buf[1];
        byte[] exp = Arrays.copyOfRange(buf, 2, expLen + 2);
        int modLen = (buf[2 + expLen] << 8) | buf[2 + expLen + 1];
        byte[] mod = Arrays.copyOfRange(buf, 2 + expLen + 2, 2 + expLen + 2 + modLen);

        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(
                new BigInteger(1, mod),
                new BigInteger(1, exp));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(pubSpec);
    }

    // команда проверки факта владения приватным ключом, который соответствует публичному ключу
    // отправляет на подпись карте случайное число, потом проверяет подпись публичным ключом
    private static boolean authenticate(CardChannel cc, RSAPublicKey pubKey) throws CardException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        int challenge = SecureRandom.getInstanceStrong().nextInt(10);
        final CommandAPDU cmd = new CommandAPDU(0x00, AUTH_INS, (byte) challenge, 0, 1);
        logCmd(cmd);
        final ResponseAPDU responseAPDU = cc.transmit(cmd);
        logAns(responseAPDU);
        if (responseAPDU.getSW() != 0x9000) {
            throw new RuntimeException();
        }
        byte[] buf = responseAPDU.getBytes();
        byte[] signature = Arrays.copyOf(buf, buf.length - 2);
        Signature signature1 = Signature.getInstance("SHA1withRSA");
        signature1.initVerify(pubKey);
        signature1.update(new byte[]{(byte) challenge});
        return signature1.verify(signature);
    }

    // команда снятия денег с карты
    // возвращает true в случае успешного снятия
    private static boolean withdraw(CardChannel cc, short withdraw_amount) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(0x00, WITHDRAW_INS, withdraw_amount >> 8, withdraw_amount & 255, 1);
        logCmd(cmd);
        final ResponseAPDU responseAPDU = cc.transmit(cmd);
        logAns(responseAPDU);
        byte[] buf = responseAPDU.getBytes();
        short balance = (short) ((buf[0] << 8) | buf[1] & 255);
        if (responseAPDU.getSW() == 0x6299) {
            LOGGER.info("NOT ENOUGH MONEY: " + balance);
            return false;
        } else if (responseAPDU.getSW() != 0x9000) {
            throw new RuntimeException();
        }
        LOGGER.info("WITHDRAW " + withdraw_amount + ", REMAINING BALANCE: " + balance);
        return true;
    }

    // команда получения имени владельца карты
    private static String getCardholderName(CardChannel cc) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(0x00, NAME_INS, 0, 0, 1);
        logCmd(cmd);
        final ResponseAPDU responseAPDU = cc.transmit(cmd);
        logAns(responseAPDU);
        if (responseAPDU.getSW() != 0x9000) {
            throw new RuntimeException();
        }
        byte[] buf = responseAPDU.getBytes();
        return new String(Arrays.copyOf(buf, buf.length - 2));
    }

    private static void printScoreboard() {
        LOGGER.info("======= SCOREBOARD =======");
        for (String name : scoreboard) {
            LOGGER.info("--- " + name);
        }
    }

    private static void processCard(CardChannel cc) throws Exception {
        // SELECT AID A00000065800000102
        CommandAPDU selectCmd = new CommandAPDU(new byte[]{
                0x00, (byte) 0xA4, 0x04, 0x00, 0x09, (byte) 0xA0,
                0x00, 0x00, 0x06, 0x58, 0x00, 0x00, 0x01, 0x02
        });
        logCmd(selectCmd);
        ResponseAPDU selectAns = cc.transmit(selectCmd);
        logAns(selectAns);

        LOGGER.info("=====> STEP 1 / GET PUBLIC KEY");
        RSAPublicKey pubKey = getPublicKey(cc);
        if (!pubKey.getModulus().toString().equals(ALLOWED_MOD) || !pubKey.getPublicExponent().toString().equals(ALLOWED_EXP)) {
            LOGGER.info("UNKNOWN PUBLIC KEY");
            return;
        }
        LOGGER.info("=====> STEP 2 / AUTHENTICATION");
        if (!authenticate(cc, pubKey)) {
            LOGGER.info("AUTHENTICATION FAILED");
            return;
        }
        LOGGER.info("=====> STEP 3 / WITHDRAW");
        if (withdraw(cc, WITHDRAW_AMOUNT)) {
            LOGGER.info("=====> STEP 4 / GET CARDHOLDER NAME");
            String name = getCardholderName(cc);
            scoreboard.add(name);
            printScoreboard();
        }
    }

    public static void main(final String[] args) throws CardException {
        System.setProperty("java.util.logging.SimpleFormatter.format",
                "[%1$tF %1$tT] [%4$-7s] %5$s %n");

        TerminalFactory factory = TerminalFactory.getDefault();
        List<CardTerminal> terminals = factory.terminals().list();
        if (terminals.isEmpty()) {
            throw new CardException("No card terminals available");
        }

        LOGGER.info("Terminals: " + terminals);

        if (!terminals.isEmpty()) {
            CardTerminal terminal = terminals.get(0);
            boolean waitForPresent = true;
            while (true) {
                if (!waitForPresent && terminal.waitForCardAbsent(1)) {
                    waitForPresent = true;
                }
                if (waitForPresent && terminal.waitForCardPresent(1)) {
                    Card card = terminal.connect("*");
                    LOGGER.info("card: " + card);
                    CardChannel cc = card.openLogicalChannel();
                    try {
                        processCard(cc);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    cc.close();
                    card.disconnect(false);
                    waitForPresent = false;
                }
            }
        } else {
            LOGGER.info("No pcsc terminal found");
        }

    }
}
