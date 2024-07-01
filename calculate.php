<?php
require 'config.php';

// Validación y saneamiento de entrada
$num1 = filter_input(INPUT_POST, 'num1', FILTER_VALIDATE_FLOAT);
$num2 = filter_input(INPUT_POST, 'num2', FILTER_VALIDATE_FLOAT);
$operation = htmlspecialchars($_POST['operation'], ENT_QUOTES, 'UTF-8');

// Validación adicional
if ($num1 === false || $num2 === false || !in_array($operation, ['sum', 'subtract', 'multiply'])) {
    handle_error(E_USER_ERROR, 'Entrada no válida.', __FILE__, __LINE__);
    exit();
}

// Realizar la operación
$result = 0;
if ($operation == 'sum') {
    $result = $num1 + $num2;
} elseif ($operation == 'subtract') {
    $result = $num1 - $num2;
} elseif ($operation == 'multiply') {
    $result = $num1 * $num2;
} else {
    handle_error(E_USER_ERROR, 'Operación no válida.', __FILE__, __LINE__);
    exit();
}

// Encriptar el resultado antes de mostrarlo (opcional, dependiendo de los requisitos)
$encrypted_result = encrypt_data((string)$result, ENCRYPTION_KEY);
$decrypted_result = decrypt_data($encrypted_result, ENCRYPTION_KEY);
?>

<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resultado de la Calculadora</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <div class="container">
        <h1>Resultado</h1>
        <div class="result">
            <p>El resultado de la operación es: <strong><?php echo htmlspecialchars($decrypted_result, ENT_QUOTES, 'UTF-8'); ?></strong></p>
            <a href="index.php" class="btn">Realizar otra operación</a>
        </div>
    </div>
</body>

</html>