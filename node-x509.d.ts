declare namespace x509 {
  function getIssuer(pathOrPEM: string): any
  function getAltNames(pathOrPEM: string): any
  function getSubject(pathOrPEM: string): any
  function parseCert(pathOrPEM: string): any
}

export = x509
