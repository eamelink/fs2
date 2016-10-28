package fs2.io.tcp.tls

import java.util.concurrent.Executors
import java.nio.channels.AsynchronousChannelGroup
import fs2._
import fs2.io.tcp
import java.net.InetSocketAddress
import javax.net.ssl.{ KeyManagerFactory, SSLContext, SSLEngine, TrustManagerFactory }
import java.security.KeyStore
import java.io.FileInputStream

object TLSTestServer {

  val es = Executors.newCachedThreadPool
  implicit val acg = AsynchronousChannelGroup.withCachedThreadPool(es, 20)
  implicit val strategy: Strategy = Strategy.fromCachedDaemonPool("task-runner")

  def main(args: Array[String]): Unit = server(args.headOption.getOrElse("echo")).run.unsafeRun

  def server(serverType: String): Stream[Task, Unit] = {
    val ps =
      tcp.server[Task](new InetSocketAddress("localhost", 9099))
      .map { (server: Stream[Task, fs2.io.tcp.Socket[Task]]) =>

        server.flatMap { socket =>
          Stream.force { TLSSocket(getSSLEngine())(socket).map { tlsSocket =>
            println("Created a TLS Socket")
            val reads = tlsSocket.reads(1024)
            val writes = tlsSocket.writes()

            serverType match {
              case "print" => Stream[Task, String]("\n\nHello!\nBye!\n").through(text.utf8Encode).to(writes)
              case "echo" => reads.through(text.utf8Decode).takeWhile(_ != "Quit\n").through(text.utf8Encode).to(writes).onFinalize(socket.endOfOutput).attempt.map {
                case Left(f) => println("Warn: stream ended with " + f)
                case Right(_) => ()
              }
            }

          }}

        }
      }

    concurrent.join(Int.MaxValue)(ps)
  }

  def getSSLEngine(): SSLEngine = {

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

    // Create the engine
    val engine = sslContext.createSSLEngine("localhost", 8844)

    // Use as client
    engine.setUseClientMode(false)
    engine.setWantClientAuth(false)
    engine.setNeedClientAuth(false)
    engine
  }

}
