import java.util.ArrayList;
import  java.util.Date;

public class Block {
    public String hash;
    public String previousHash;
    private String data;
    private Long timestamp;
    private int nonce;

    public String merkleRoot;
    public ArrayList<Transaction> transactions = new ArrayList<Transaction>();


    //Constructor

   public Block(String previousHash){
        this.previousHash = previousHash;
        this.timestamp = new Date().getTime();

        this.hash = calculateHash();
    }


    public String calculateHash(){
       String calculatehash = HashUtil.applySha256(
               previousHash + Long.toString(timestamp)+ merkleRoot
       );

       return calculatehash;
    }

    public void mineBlock(int difficulty){
        merkleRoot = HashUtil.getMerkleRoot(transactions);

       String target = new String(new char[difficulty]).replace('\0', '0');

       while (!hash.substring(0, difficulty). equals(target)){
           nonce++;
           hash = calculateHash();
       }

        System.out.println("Block Mined!!! : " + hash);
    }

    public  boolean addTransaction(Transaction transaction){
        if(transaction == null) return false;
        if((previousHash != "0")) {
            if((transaction.processTransaction() != true)) {
                System.out.println("Transaction failed to process. Discarded.");
                return false;
            }
        }
        transactions.add(transaction);
        System.out.println("Transaction Successfully added to Block");
        return true;
    }

}
