<?php
  if(isset($_POST['username']) && isset($_POST['password'])) {
      $username = $_POST['username'];
      $password = $_POST['password'];
     
      $conn = new mysqli("localhost", "root", "password", "users_db");
      if ($conn->connect_error) {
          die("Connection failed: " . $conn->connect_error);
      }
     
      $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
      $result = $conn->query($sql);
     
      if ($result->num_rows > 0) {
          echo "Welcome, " . htmlspecialchars($username);
      } else {
          echo "Invalid credentials.";
      }
  }
?>