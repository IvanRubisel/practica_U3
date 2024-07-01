<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Calculadora Básica</title>
    <link rel="stylesheet" href="style.css">
</head>

<body>
    <div class="container">
        <h1>Calculadora Básica</h1>
        <form action="calculate.php" method="post">
            <div class="form-group">
                <label for="num1">Número 1:</label>
                <input type="number" step="any" id="num1" name="num1" required>
            </div>

            <div class="form-group">
                <label for="num2">Número 2:</label>
                <input type="number" step="any" id="num2" name="num2" required>
            </div>

            <div class="form-group">
                <label for="operation">Operación:</label>
                <select id="operation" name="operation">
                    <option value="sum">Suma</option>
                    <option value="subtract">Resta</option>
                    <option value="multiply">Multiplicacion</option>
                    <option value="divide">Division</option>
                </select>
            </div>

            <button type="submit" class="btn">Calcular</button>
        </form>
    </div>
</body>

</html>