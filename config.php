<?php
session_start();

// Configuración de la aplicación
define('APP_DEBUG', true);

// Clave para encriptación (debe ser cambiada a algo seguro y almacenada de manera segura)
define('ENCRYPTION_KEY', 'your-secret-key');

// Función para registrar errores
function log_error($message) {
    error_log($message, 3, 'errors.log');
}

// Función para manejar errores de forma personalizada
function handle_error($errno, $errstr, $errfile, $errline) {
    if (!(error_reporting() & $errno)) {
        return;
    }

    $error_message = "Error [$errno]: $errstr en $errfile:$errline";
    log_error($error_message);

    if (APP_DEBUG) {
        echo $error_message;
    } else {
        echo "Ocurrió un error. Por favor, intenta nuevamente más tarde.";
    }

    return true;
}

set_error_handler('handle_error');

// Funciones criptográficas
function generate_token($length = 32) {
    return bin2hex(random_bytes($length));
}

// Encriptación de datos sensibles (Ejemplo: almacenar información encriptada)
function encrypt_data($data, $key) {
    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt($data, 'aes-256-cbc', $key, 0, $iv);
    return base64_encode($encrypted . '::' . $iv);
}

function decrypt_data($data, $key) {
    list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
    return openssl_decrypt($encrypted_data, 'aes-256-cbc', $key, 0, $iv);
}
?>
