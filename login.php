<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Connect to the database
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "job_portal";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form data is set
if (!isset($_POST['email']) || !isset($_POST['password']) || !isset($_POST['user_type'])) {
    die("Error: Required fields are missing. Please fill out the login form completely.");
}

// Get the POST data from the login form
$email = $_POST['email'];
$raw_password = $_POST['password']; // The entered password
$user_type = $_POST['user_type'];

// Debugging: Check if the data is coming in correctly
echo "<p>Debug: Email: $email, User Type: $user_type</p>";

// Select the user from the users table
$stmt = $conn->prepare("SELECT user_id, password FROM users WHERE email = ? AND user_type = ?");
$stmt->bind_param("ss", $email, $user_type);
$stmt->execute();
$stmt->store_result();

// Check if the user exists
if ($stmt->num_rows > 0) {
    $stmt->bind_result($user_id, $hashed_password);
    $stmt->fetch();

    // Debugging: Check if we fetched the hashed password and user_id
    echo "<p>Debug: Fetched Hashed Password = $hashed_password, User ID = $user_id</p>";

    // Verify the password
    if (password_verify($raw_password, $hashed_password)) {
        // Password is correct, start the session
        session_start();
        $_SESSION['email'] = $email;
        $_SESSION['user_type'] = $user_type;
        $_SESSION['user_id'] = $user_id; // Store the user_id in the session

        // Redirect based on user type
        if ($user_type === 'seeker') {
            echo "Login successful! Redirecting to seeker dashboard...";
            header("Location: seeker_dashboard.php");
        } else {
            echo "Login successful! Redirecting to company dashboard...";
            header("Location: company_dashboard.php");
        }
        exit();
    } else {
        // Invalid password
        echo "Invalid password. Please try again.";
    }
} else {
    // No user found
    echo "No account found with this email.";
}

$stmt->close();
$conn->close();
?>
