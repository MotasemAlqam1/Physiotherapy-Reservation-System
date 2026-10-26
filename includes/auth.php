<?php

function requireAuth(PDO $pdo): array
{
    if (
        !isset($_SESSION["user_id"]) ||
        filter_var(
            $_SESSION["user_id"] ?? null,
            FILTER_VALIDATE_INT,
            ["options" => ["min_range" => 1]]
        ) === false
    ) {
        header("Location: /reservation-system/login.php");
        exit;
    }

    try {
        $sql = "SELECT id,full_name,role,is_active
        FROM users WHERE id=:id LIMIT 1";

        $stmt = $pdo->prepare($sql);
        $stmt->execute(["id" => $_SESSION["user_id"]]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (PDOException $e) {
        error_log($e->getMessage());
        http_response_code(500);
        exit("Unable to verify your account.");
    }

    if($user === false || (int) $user["is_active"] !== 1)
        {
            session_unset();
            session_destroy();

            header("Location: /reservation-system/login.php");
            exit;
        }
    
    return $user;
}

function requireAdmin(PDO $pdo):array
{
    $currentUser = requireAuth($pdo);
    if($currentUser["role"] !== "admin")
        {
            http_response_code(403);
            exit("Access denied");
        }
    return $currentUser;
}

