package fs2.io
package tcp
package tls

import java.net.InetSocketAddress
import java.nio.channels.AsynchronousChannelGroup
import java.security.KeyStore
import javax.net.ssl.{ KeyManagerFactory, SSLContext, SSLEngine, TrustManagerFactory }
import java.io.FileInputStream

import fs2._

import fs2.io.TestUtil._
import fs2.Stream._

// import fs2.util.UF1
// import org.scalacheck.Gen

object TLSSocketSpec {
  implicit val tlsACG : AsynchronousChannelGroup = namedACG("tls")

  lazy val sslContext = {
    // Create and initialize the SSLContext with key material
    val passphrase = "fs2tls".toCharArray()
    val trustPassphrase = "fs2tls".toCharArray()
    // First initialize the key and trust material
    val ksKeys = KeyStore.getInstance("JKS")
    ksKeys.load(new FileInputStream("keystore.jks"), passphrase)
    val ksTrust = KeyStore.getInstance("JKS")
    ksTrust.load(new FileInputStream("keystore.jks"), trustPassphrase)

    // KeyManagers decide which key material to use
    val kmf = KeyManagerFactory.getInstance("SunX509")
    kmf.init(ksKeys, passphrase)

    // TrustManagers decide whether to allow connections
    val tmf = TrustManagerFactory.getInstance("SunX509")
    tmf.init(ksTrust)

    val sslContext = SSLContext.getInstance("TLS")
    sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null)
    sslContext
  }

  def getSSLEngine(client: Boolean): SSLEngine = {
    // Create the engine
    val engine = sslContext.createSSLEngine("localhost", 8844)

    // Use as client
    engine.setUseClientMode(client)
    engine.setWantClientAuth(false)
    engine.setNeedClientAuth(false)
    engine
  }
}

class TLSSocketSpec extends Fs2Spec {


  import TLSSocketSpec._

    "tls" - {

      "read from printserver" in {

        val serverTask: Task[Unit] = server(printBehaviour).drain.run
        // TODO, actually test something

      }

    }

  type Behaviour = TLSSocket[Task] => Stream[Task, Unit]

  val echoBehaviour = (s: TLSSocket[Task]) =>
    s.reads(1024).through(text.utf8Decode).takeWhile(_ != "Quit\n").through(text.utf8Encode).to(s.writes()).onFinalize(s.endOfOutput).attempt.map {
      case Left(f) => println("Warn: stream ended with " + f)
      case Right(_) => ()
    }

  val printBehaviour: Behaviour = s => Stream[Task, String]("\n\nHello!\nBye!\n").through(text.utf8Encode).to(s.writes())

  def server(behaviour: Behaviour): Stream[Task, Unit] = {
    val ps = tcp.server[Task](new InetSocketAddress("localhost", 9099)).flatMap { (server: Stream[Task, fs2.io.tcp.Socket[Task]]) =>
        Stream.emit(server.flatMap { socket =>
          Stream.force { TLSSocket(getSSLEngine(false))(socket).map { behaviour }}
        })
      }

    concurrent.join(Int.MaxValue)(ps)
  }



}
