<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    include "../connection.php"; // Ensure this file defines $conn (PDO connection)

    $email = trim($_POST["email"]);
    $password = $_POST["password"];

    // Check if fields are empty
    if (empty($email) || empty($password)) {
        header("Location: adminLoginPage.php?error=" . urlencode("Please fill in all fields."));
        exit();
    }

    try {
        // Use TOP 1 for SQL Server to fetch only the first match
        $stmt = $conn->prepare("SELECT TOP 1 * FROM heather.admins WHERE ADMIN_EMAIL = ? OR ADMIN_CONTACT = ?");
        $stmt->execute([$email, $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['ADMIN_PASS'])) {
            session_regenerate_id(true); // Secure the session
            $_SESSION["USER_TYPE"] = $user["USER_TYPE"];
            $_SESSION["user"] = $user["ADMIN_EMAIL"];

            if ($user["USER_TYPE"] === "Admin") {
                header("Location: adminDashboard.php");
                exit();
            } else {
                header("Location: adminLoginPage.php?error=" . urlencode("Access denied for this user type."));
                exit();
            }
        } else {
            header("Location: adminLoginPage.php?error=" . urlencode("Incorrect email/phone number or password."));
            exit();
        }
    } catch (PDOException $e) {
        // Log the error for debugging (do not display it to users)
        error_log("Login error: " . $e->getMessage());
        header("Location: adminLoginPage.php?error=" . urlencode("A database error occurred. Please try again later."));
        exit();
    }
} else {
    // If accessed directly without POST, redirect to login page
    header("Location: adminLoginPage.php");
    exit();
}
?>
