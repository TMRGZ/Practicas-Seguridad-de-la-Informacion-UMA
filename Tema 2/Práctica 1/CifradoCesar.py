def cifradoCesarAlfabetoIngles(cadena, m):
    resultado = ""
    i = 0

    while i < len(cadena):
        orden_claro = ord(cadena[i])
        orden_cifrado = 0

        if 65 <= orden_claro <= 90:
            orden_cifrado = (((orden_claro - 65) + m) % 26) + 65
        elif 97 <= orden_claro <= 122:
            orden_cifrado = (((orden_claro - 97) + m) % 26) + 97

        resultado = resultado + chr(orden_cifrado)
        i = i + 1

    return resultado


def descifradoCesarAlfabetoIngles(cadena, m):
    resultado = ""
    i = 0

    while i < len(cadena):
        ordenClaro = ord(cadena[i])
        ordenCifrado = 0

        if 65 <= ordenClaro <= 90:
            ordenCifrado = (((ordenClaro - 65) - m) % 26) + 65
        elif 97 <= ordenClaro <= 122:
            ordenCifrado = (((ordenClaro - 97) - m) % 26) + 97

        resultado = resultado + chr(ordenCifrado)
        i = i + 1

    return resultado


M = 3
textoACifrar = "prueba"

print("Cifrar prueba con M= " + str(M))
print(cifradoCesarAlfabetoIngles(textoACifrar, M))

print("Descifrado")
print(descifradoCesarAlfabetoIngles(cifradoCesarAlfabetoIngles(textoACifrar, M), M))
