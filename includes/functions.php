<?php
require "config.php";

function connect()
{
    $mysqli = new mysqli(SERVER, USERNAME, PASSWORD, DATABASE);

    if ($mysqli->connect_errno != 0) {

        $error = $mysqli->connect_error;

        return false;

    } else {

        return $mysqli;

    }
}


function registerUser($email, $username, $password, $confirm_password)
{

    $mysqli = connect();

    $args = func_get_args();

    $args = array_map(function ($value) {

        return trim($value);

    }, $args);

    foreach ($args as $value) {

        if (empty($value)) {

            return "All Fields are required";

        }

    }

    foreach ($args as $value) {

        if (preg_match("/([<|>])/", $value)) {

            return "<> Characters are not allowed";

        }

    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        return "Email is not valid";

    }

    $sql = "SELECT email FROM user where email = ?";

    $stmt = $mysqli->prepare($sql);

    $stmt->bind_param('s', $email);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data != NULL) {

        return "email already exists Please use different email";

    }

    if (strlen($username) > 50) {

        return "Username is too long";

    }

    $stmt = $mysqli->prepare("SELECT username FROM user WHERE username = ?");

    $stmt->bind_param("s", $username);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data != null) {
        return "Username already exists.";
    }

    if (strlen($password) > 50) {

        return "Password is too long";

    }

    if ($password != $confirm_password) {

        return "Passwords do not match";

    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $mysqli->prepare("INSERT INTO user(username, password, email) VALUES(?,?,?)");

    $stmt->bind_param("sss", $username, $hashed_password, $email);

    $stmt->execute();

    if ($stmt->affected_rows != 1) {

        return "An error occurred,Please try again";

    } else {

        return "success";

    }

}






function login($username, $password)
{

    $mysqli = connect();

    $username = trim($username);

    $password = trim($password);

    if ($username == "" || $password == "") {

        return "Both fields are required";

    }

    $username = filter_var($username, FILTER_SANITIZE_STRING);
    $password = filter_var($password, FILTER_SANITIZE_STRING);

    $sql = "SELECT username, password, type FROM users WHERE username=?";

    $stmt = $mysqli->prepare($sql);

    $stmt->bind_param("s", $username);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data == null) {



        return "username";

    }

    if (
        $password != $data['password']
    ) {

        return "password";

    } else {

        $_SESSION['user_id'] = $data['s_no'];
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['type'] = $data['type'];
        header('Location: index.php');

    }

}






function logout()
{

    session_destroy();

    header("location:login.php");

    exit();

}



function add_employee($name, $email, $password, $employee_id, $phone, $department, $designation, $picture, $joining_date)
{

}


function edit_employee($name, $email, $password, $employee_id, $phone, $department, $designation, $joining_date)
{

}

function add_client($first_name, $last_name, $email, $username, $client_id, $phone, $company_name, $address, $picture)
{

}

function edit_client($first_name, $last_name, $username, $email, $client_id, $phone, $company_name, $address)
{

}

function get_employees()
{

    $mysqli = connect();

    $sql = "SELECT * FROM employees";

    $stmt = $mysqli->prepare($sql);

    $stmt->execute();

    $result = $stmt->get_result();

    return $result->fetch_all(MYSQLI_ASSOC);

}
function get_projects()
{

    $mysqli = connect();

    $sql = "SELECT * FROM projects";

    $stmt = $mysqli->prepare($sql);

    $stmt->execute();

    $result = $stmt->get_result();

    return $result->fetch_all(MYSQLI_ASSOC);

}
function get_employee_images($id)
{

    $mysqli = connect();

    $sql = "SELECT Picture FROM employees WHERE id  = $id";

    $stmt = $mysqli->prepare($sql);

    $stmt->execute();

    $result = $stmt->get_result();

    return $result->fetch_assoc();

}
function get_employees()
{

    $mysqli = connect();

    $sql = "SELECT * FROM employees";

    $stmt = $mysqli->prepare($sql);

    $stmt->execute();

    $result = $stmt->get_result();

    return $result->fetch_all(MYSQLI_ASSOC);

}

?>