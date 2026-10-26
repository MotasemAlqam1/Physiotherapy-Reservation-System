<?php

session_start();

if ($_SERVER["REQUEST_METHOD"] !== "POST")
    {
        http_response_code(405);
        exit("Method not allowed");
    }
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)) 
        {
        http_response_code(403);
        exit("Invalid CSRF token.");
        }

}

session_unset();

if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();

    setcookie(
        session_name(),
        "",
        [
            "expires" => time() - 3600,
            "path" => $params["path"],
            "domain" => $params["domain"],
            "secure" => $params["secure"],
            "httponly" => $params["httponly"],
            "samesite" => $params["samesite"] ?? "Lax"
        ]
    );
}

session_destroy();

header("Location: /reservation-system/login.php", true, 303);
exit;