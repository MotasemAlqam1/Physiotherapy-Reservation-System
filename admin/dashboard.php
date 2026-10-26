<?php

session_start();

require_once __DIR__ . "/../config/database.php";
require_once __DIR__ . "/../includes/auth.php";

$currentUser = requireAdmin($pdo);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
</head>
<body>

    <h1>Admin Dashboard</h1>

    <p>
        Welcome,
        <?= htmlspecialchars($currentAdmin["full_name"], ENT_QUOTES, "UTF-8") ?>
    </p>

</body>
</html>