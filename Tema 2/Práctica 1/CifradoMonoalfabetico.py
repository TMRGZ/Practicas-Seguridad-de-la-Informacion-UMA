def cifradoMonoalfabetico(cadena, clave):
    resultado = ""
    i = 0

    while i < len(cadena):
        ordenClaroCadena = ord(cadena[i])
        ordenClaroClave = ord(clave[i%len(clave)])
        ordenCifrado = 0

        if ordenClaroCadena >= 65 and ordenClaroCadena <= 90:
            ordenCifrado = (((ordenClaroCadena - 65) + (ordenClaroClave-64)) % 26) + 65
        elif ordenClaroCadena >= 97 and ordenClaroCadena <= 122:
            ordenCifrado = (((ordenClaroCadena - 97) + (ordenClaroClave-96)) % 26) + 97

        resultado = resultado + chr(ordenCifrado)
        i = i + 1

    return resultado


def descifradoMonoalfabetico(cadena, clave):
    resultado = ""
    i = 0

    while i < len(cadena):
        ordenClaroCadena = ord(cadena[i])
        ordenClaroClave = ord(clave[i%len(clave)])
        ordenCifrado = 0

        if ordenClaroCadena >= 65 and ordenClaroCadena <= 90:
            ordenCifrado = (((ordenClaroCadena - 65) - (ordenClaroClave-64)) % 26) + 65
        elif ordenClaroCadena >= 97 and ordenClaroCadena <= 122:
            ordenCifrado = (((ordenClaroCadena - 97) - (ordenClaroClave-96)) % 26) + 97

        resultado = resultado + chr(ordenCifrado)
        i = i + 1

    return resultado

textoACifrar = "HOLAAMIGOS"
textoClave = "CIFRA"


print("Cifrar prueba con clave " + textoClave)
print(cifradoMonoalfabetico(textoACifrar, textoClave))

print("Descifrado")
print(descifradoMonoalfabetico(cifradoMonoalfabetico(textoACifrar, textoClave), textoClave))