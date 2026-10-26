<?php

session_start();

require_once __DIR__ . "/config/database.php";
require_once __DIR__ . "/includes/auth.php";

$currentUser = requireAuth($pdo);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
</head>
<body>

    <h1>
        Welcome,
        <?= htmlspecialchars($currentUser["full_name"], ENT_QUOTES, "UTF-8") ?>
    </h1>

    <p>You are successfully authenticated.</p>

    <form action="logout.php" method="POST">
    <input
        type="hidden"
        name="csrf_token"
        value="<?= htmlspecialchars($_SESSION["csrf_token"], ENT_QUOTES, 'UTF-8') ?>"
    >

    <button type="submit">Logout</button>
</form>
</body>
</html>