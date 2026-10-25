<?php

session_start();

$successMessage = $_SESSION["success_message"] ?? "";
unset($_SESSION["success_message"]);

require_once __DIR__ . "/config/database.php";

$errors = [];
$email = "";

if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)
    ) {
        http_response_code(403);
        exit("Invalid CSRF token.");
    }

    $email = $_POST["email"] ?? "";
    $password = $_POST["password"] ?? "";

    if (!is_string($email) || !is_string($password)) {
        http_response_code(400);
        exit("Invalid input.");
    }

    $email = trim($email);

    if ($email === "") {
        $errors[] = "Email is required";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email address";
    }

    if ($password === "") {
        $errors[] = "Password is required";
    }

    if (empty($errors)) {

        try {
            $sql = "SELECT id, full_name, email,
                           password_hash, role, is_active
                    FROM users
                    WHERE email = :email
                    LIMIT 1";

            $stmt = $pdo->prepare($sql);

            $stmt->execute(["email" => $email]);

            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user || !password_verify($password, $user["password_hash"])) {
                $errors[] = "Invalid email or password";
            } elseif ((int) $user["is_active"] !== 1) {
                $errors[] = "Invalid email or password";
            } elseif (!in_array($user["role"], ["admin", "user"], true)) {
                $errors[] = "Invalid email or password";
            } else {

                session_regenerate_id(true);
                $_SESSION["user_id"] = $user["id"];
                $_SESSION["full_name"] = $user["full_name"];
                $_SESSION["role"] = $user["role"];

                if ($user["role"] === "admin") {
                    header("Location: admin/dashboard.php", true, 303);
                    exit;
                } elseif ($user["role"] === "user") {
                    header("Location: index.php", true, 303);
                    exit;
                }
            }

        } catch (PDOException $e) {

            error_log($e->getMessage());
            $errors[] = "Login failed. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
</head>

<body>
    <h2>Login to Your Account</h2>
    <?php if (is_string($successMessage) && $successMessage !== ""): ?>
        <p>
            <?= htmlspecialchars($successMessage, ENT_QUOTES, "UTF-8") ?>
        </p>
    <?php endif; ?>

    <?php foreach ($errors as $error): ?>
        <p><?= htmlspecialchars($error, ENT_QUOTES, "UTF-8") ?></p>
    <?php endforeach; ?>

    <form action="login.php" method="POST">
        <label for="email">Email</label>
        <input type="email" id="email" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>">

        <br><br>

        <label for="password">Password</label>
        <input type="password" id="password" name="password" autocomplete="current-password">

        <br><br>
        <input type="hidden" name="csrf_token"
            value="<?= htmlspecialchars($_SESSION["csrf_token"], ENT_QUOTES, "UTF-8") ?>">
        <button type="submit">Login</button>
    </form>
    <p>
        Don't have an account?
        <a href="register.php">Register here</a>
    </p>
</body>

</html>