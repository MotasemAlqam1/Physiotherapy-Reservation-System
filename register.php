<?php

session_start();

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

require_once __DIR__ . "/config/database.php";

$errors = [];
$full_name = "";
$email = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)
    ) {
        http_response_code(403);
        exit("Invalid CSRF token.");
    }



    $full_name = $_POST["full_name"] ?? "";
    $email = $_POST["email"] ?? "";
    $password = $_POST["password"] ?? "";

    if (
        !is_string($full_name) ||
        !is_string($email) ||
        !is_string($password)
    ) {
        http_response_code(400);
        exit("Invalid input.");
    }

    $full_name = trim($full_name);
    $email = trim($email);

    // Validation
    if ($full_name === "") {
        $errors[] = "full name is required";
    }

    if ($email === "") {
        $errors[] = "Email is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email address";
    }

    if ($password === "") {
        $errors[] = "Password is required";
    } elseif (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters";
    }

    if (empty($errors)) {
        try {
            // Check duplicate email
            $stmt = $pdo->prepare(
                "SELECT id FROM users WHERE email = :email"
            );
            $stmt->execute(["email" => $email]);

            if ($stmt->fetch(PDO::FETCH_ASSOC) !== false) {
                $errors[] = "Email already exists";
            }

            // Insert only when validation passes
            if (empty($errors)) {
                $passwordHash = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );

                $sql = "INSERT INTO users (full_name, email, password_hash)
                        VALUES (:full_name, :email, :password_hash)";

                $stmt = $pdo->prepare($sql);
                $stmt->execute([
                    "full_name" => $full_name,
                    "email" => $email,
                    "password_hash" => $passwordHash
                ]);

                $_SESSION["success_message"] = "Account created successfully!";

                header("Location: login.php", true, 303);
                exit;
            }

        } catch (PDOException $e) {
            error_log($e->getMessage());

            if (($e->errorInfo[1] ?? null) === 1062) {
                $errors[] = "Email already exists";
            } else {
                $errors[] = "Registration failed. Please try again.";
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
</head>

<body>
    <h2>Create Account</h2>

    <?php foreach ($errors as $error): ?>
        <p><?= htmlspecialchars($error, ENT_QUOTES, "UTF-8") ?></p>
    <?php endforeach; ?>

    <form action="register.php" method="POST">

        <label for="full_name">Full Name</label>
        <input type="text" name="full_name" id="full_name"
            value="<?= htmlspecialchars($full_name, ENT_QUOTES, 'UTF-8') ?>">
        <br><br>

        <label for="email">Email</label>
        <input type="email" name="email" id="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>">

        <br><br>

        <label for="password">Password</label>
        <input type="password" name="password" id="password">

        <br><br>

        <input type="hidden" name="csrf_token"
            value="<?= htmlspecialchars($_SESSION["csrf_token"], ENT_QUOTES, "UTF-8") ?>">

            
        <button type="submit">Register</button>

    </form>
</body>

</html>