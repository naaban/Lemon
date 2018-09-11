<?php

class DbHandler {
 
    private $conn;
 
    function __construct() {
        require_once dirname(__FILE__) . './DbConnect.php';
        // opening db connection
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

      /**
     * Creating new user
     * @param String $name User full name
     * @param String $email User login email id
     * @param String $password User login password
     */ 
    public function createUser($name, $email, $password) {

        require_once 'PassHash.php';
        $response = array();

        if(!$this->isUserExists($email)){

            // Generating password hash
            $password_hash = PassHash::hash($password);

            //Generating api key
            $api_key = $this->generateApiKey();

            //insertQury
            $stmt = $this->conn->prepare("INSERT INTO user_details(name , email , password_hash ,apikey , status ) VALUES ( ? ,? ,? , ?, 1)");
            $stmt = $this->bind_params("ssss",$name , $email , $password_hash ,$api_key);

            $result = $stmt->execute();

            $stmt->close();

            if($result){

                return USER_CREATED_SUCCESSFULLY;
            }
            else{
                return USER_CREATE_FAILED;
            }
        }
        else{
            return USER_ALREADY_EXISTED;
        }
        return $response;

        }


   /**
     * Checking user login
     * @param String $email User login email id
     * @param String $password User login password
     * @return boolean User login status success/fail
     */
    public function checkLogin($email, $password) {
        // fetching user by email
        $stmt = $this->conn->prepare("SELECT password_hash FROM user_details WHERE email = ?");
 
        $stmt->bind_param("s", $email);
 
        $stmt->execute();
 
        $stmt->bind_result($password_hash);
 
        $stmt->store_result();
 
        if ($stmt->num_rows > 0) {
            // Found user with the email
            // Now verify the password
 
            $stmt->fetch();
 
            $stmt->close();
 
            if (PassHash::check_password($password_hash, $password)) {
                // User password is correct
                return TRUE;
            } else {
                // user password is incorrect
                return FALSE;
            }
        } else {
            $stmt->close();
 
            // user not existed with the email
            return FALSE;
        }
    }
 
    /**
     * Checking for duplicate user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT id from user_details WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

     /**
     * Fetching user by email
     * @param String $email User email id
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT name, email, api_key, status, created_at FROM user_details WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $user = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }
 
    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM user_details WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $api_key = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }
 
    /**
     * Fetching user id by api key
     * @param String $api_key user api key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM user_details WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $user_id = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }
 
    /**
     * Validating user api key
     * If the api key is there in db, it is a valid key
     * @param String $api_key user api key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from user_details WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }
 
    /**
     * Generating random Unique MD5 String for user Api key
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

    /////////////////
    //////ADMIN//////
    /////////////////
    
    /**
     * Creation of Product
     * @param array $data uploaded by admin
     */

    private function addProduct($product_type,$product_name, $product_des ,$price , $instock , $coupon_code){

        $response = array();
        $stmt = $this->conn->prepare("INSERT INTO products(product_type , product_name , product_des ,price , instock , coupon_code ) VALUES ( ? ,? ,? , ?, ?)");
        $stmt = $this->bind_params("issiis",$product_type,$product_name, $product_des ,$price , $instock , $coupon_code );
        $result = $stmt->execute();
        $stmt->close();
          return $response;

    }

    private function getProducts(){
        $stmt = $this->conn->prepare("SELECT * FROM products as prod JOIN attributes as attr ON attr.attribute_id = prod.product_type");
        if($stmt->execute()){
        $result = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        return $result;
        }
        else {
            return NULL;
        }
        
     }

     private function updateProduct($product_type,$product_name, $product_des ,$price , $instock , $coupon_code,$product_id){

        $response = array();
        $stmt = $this->conn->prepare("UPDATE products SET product_type = ? , product_name = ?, product_des = ?,price = ?, instock = ?, coupon_code = ? WHERE product_id = ?");
        $stmt = $this->bind_params("issiisi",$product_type,$product_name, $product_des ,$price , $instock , $coupon_code ,$product_id);
        $result = $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();

          return $num_affected_rows > 0;

    }

    private function deleteProduct($product_id){
        $stmt = $this->conn->prepare("DELETE product FROM products product, cart carts WHERE products.product_id = ? AND carts.product_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;

    }

}
?>