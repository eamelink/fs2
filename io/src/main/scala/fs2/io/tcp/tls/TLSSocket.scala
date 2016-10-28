package fs2.io.tcp.tls

import javax.net.ssl._
import fs2.Strategy
import fs2._
import fs2.util._
import fs2.util.syntax._
import fs2.io.tcp.Socket
import java.nio.ByteBuffer
import fs2.async.mutable.Semaphore
import java.security.cert.Certificate
import scala.concurrent.duration._

trait TLSSocket[F[_]] extends Socket[F] {

  /**
   * Get the peer certificate chain, this F won't complete until the session has been established.
   *
   * The Option is a None when no peer authentication is provided.
   */
  def peerCertificates: F[Option[List[Certificate]]]

}

object TLSSocket {

  private def chunk(buffer: ByteBuffer, maxSize: Option[Int] = None): Chunk[Byte] = {
    val size = maxSize map { math.min(buffer.remaining, _) } getOrElse buffer.remaining
    val array = new Array[Byte](size)
    buffer.get(array)
    val chunk = Chunk.bytes(array)
    chunk
  }

  private def allocateBufferFlipped(size: Int): ByteBuffer = {
    val buffer = ByteBuffer.allocate(size)
    buffer.flip()
    buffer
  }

  private def runWith[F[_], A](s: Semaphore[F])(t: F[A])(implicit F: Catchable[F]): F[A] = for {
    _ <- s.decrement
    attempt <- t.attempt
    _ <- s.increment
    result <- attempt.fold(F.fail, F.pure)
  } yield result

  def apply[F[_]](sslEngine: SSLEngine)(socket: Socket[F])(implicit strategy: Strategy, F: Async[F], F2: Catchable[F]): F[TLSSocket[F]] =
    for {
      readSemaphore <- Semaphore[F](1)
      writeSemaphore <- Semaphore[F](1)
      initialHandshakeDone <- F.ref[Unit] // Gets set when the initial handshake is done.
    } yield {

      var netReadBuffer: ByteBuffer = allocateBufferFlipped(sslEngine.getSession.getPacketBufferSize)
      var appReadBuffer: ByteBuffer = allocateBufferFlipped(sslEngine.getSession.getApplicationBufferSize)
      val netWriteBuffer: ByteBuffer = allocateBufferFlipped(sslEngine.getSession.getPacketBufferSize)
      val appWriteBuffer: ByteBuffer = allocateBufferFlipped(sslEngine.getSession.getApplicationBufferSize)

      def write0(bytes: Chunk[Byte], timeout: Option[FiniteDuration]): F[Unit] = F.suspend {
        val start = System.currentTimeMillis()
        runWith(writeSemaphore) {
          F.delay {
            appWriteBuffer.compact()
            appWriteBuffer.put(bytes.toBytes.values)
            appWriteBuffer.flip()
          }
        }.flatMap { _ =>
          writeAppWriteBuffer(remaining(timeout, start))
        }
      }

      def wrapAndWriteStep(timeout: Option[FiniteDuration]): F[SSLEngineResult.HandshakeStatus] = F.suspend {
        if(sslEngine.isOutboundDone) {
          F.delay(sslEngine.getHandshakeStatus) // TODO, throw a fuss if there are app bytes or net bytes left.
        } else {
          netWriteBuffer.compact()
          val sslEngineResult = sslEngine.wrap(appWriteBuffer, netWriteBuffer)
          netWriteBuffer.flip()

          val task = sslEngineResult.getStatus() match {
            case SSLEngineResult.Status.OK =>
              if(sslEngineResult.bytesProduced > 0) socket.write(chunk(netWriteBuffer), timeout)
              else F.pure(())
            case SSLEngineResult.Status.CLOSED =>
              if(sslEngineResult.bytesProduced > 0) socket.write(chunk(netWriteBuffer), timeout)
              else F.pure(())
            case SSLEngineResult.Status.BUFFER_OVERFLOW =>
              F.delay { sys.error("TODO") }
            case SSLEngineResult.Status.BUFFER_UNDERFLOW =>
              F.delay { sys.error("Should not happen") } // TODO, mention possible bug in FS2
          }

          task.map { _ => sslEngineResult.getHandshakeStatus }
        }
      }

      def writeAppWriteBuffer(timeout: Option[FiniteDuration]): F[Unit] = F.suspend {
        val start = System.currentTimeMillis()
        if(appWriteBuffer.remaining > 0) {
          runWith(writeSemaphore) {
            wrapAndWriteStep(timeout)
          }.flatMap {
            case SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING => F.pure(())
            case other =>
              handleHandshake(other, remaining(timeout, start)).flatMap { _ =>
                writeAppWriteBuffer(remaining(timeout, start))
              }
          }
        } else F.pure(())
      }

      def closeOutbound0: F[Unit] =
        runWith(writeSemaphore) {
          for {
            _ <- F.delay { sslEngine.closeOutbound }
            // TODO, check if a malicious client can't keep the connection open by stalling this, without the timeout
            _ <- wrapAndWriteStep(None) // FIXME, we may need multiple WRAP's for the closing handshake, so we should act on the result
          } yield ()
        }

      def runEngineTasks: F[Unit] = {
        val stream: Stream[F, Unit] = Stream.unfold(sslEngine) { case engine =>
          // TODO, does this run the Fs concurrently? On the proper strategy?
          Option(engine.getDelegatedTask).map { case runnable => runnable -> engine }
        }.map { _.run }

        stream.run
      }

      def growAppReadBuffer = {
        appReadBuffer.compact()
        val newSize = sslEngine.getSession.getApplicationBufferSize - appReadBuffer.remaining
        val old = appReadBuffer
        appReadBuffer = ByteBuffer.allocate(newSize)
        appReadBuffer.put(old)
        appReadBuffer.flip()
      }

      def assertNetBytes(timeout: Option[FiniteDuration]): F[Unit] =
        F.suspend {
          if(netReadBuffer.remaining > 0) F.pure(())
          else readNetBytes(timeout)
        }

      // Read more bytes into the netReadBuffer, growing it if needed
      def readNetBytes(timeout: Option[FiniteDuration]): F[Unit] = F.suspend {
        netReadBuffer.compact()

        socket.read(netReadBuffer.remaining, timeout) map {
          case Some(chunk) =>
            netReadBuffer.put(chunk.toBytes.values, 0, chunk.size)
            val _ = netReadBuffer.flip()
          case None =>
            netReadBuffer.flip()
            sslEngine.closeInbound()
        }
      }

      def readAndUnwrapStep(timeout: Option[FiniteDuration]): F[SSLEngineResult.HandshakeStatus] = F.suspend {
        val start = System.currentTimeMillis()
        assertNetBytes(timeout).flatMap { _ =>

          appReadBuffer.compact()
          val result = sslEngine.unwrap(netReadBuffer, appReadBuffer)
          appReadBuffer.flip()

          result.getStatus match {
            case SSLEngineResult.Status.CLOSED => F.pure(result.getHandshakeStatus)
            case SSLEngineResult.Status.BUFFER_OVERFLOW =>
              F.delay { growAppReadBuffer } >> readAndUnwrapStep(remaining(timeout, start)) // TODO, should we have a functino that skips the read part?
            case SSLEngineResult.Status.BUFFER_UNDERFLOW =>
              readNetBytes(remaining(timeout, start)).flatMap { _ =>
                readAndUnwrapStep(remaining(timeout, start)) // TODO, increase buffer
              }
            case SSLEngineResult.Status.OK => F.delay { result.getHandshakeStatus }
          }
        }
      }

      // After this method there is at least one byte in the appReadBuffer
      def readAndUnwrap(timeout: Option[FiniteDuration]): F[Unit] = F.suspend {
        val start = System.currentTimeMillis()
        runWith(readSemaphore) {
          if(appReadBuffer.remaining > 0) F.pure(None)
          else readAndUnwrapStep(timeout).map { Some(_) }
        }.flatMap {
          case None => F.pure(())
          case Some(SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) => F.pure(())
          case Some(other) =>
            handleHandshake(other, remaining(timeout, start)).flatMap { _ =>
              if(sslEngine.isInboundDone) F.pure(())
              else readAndUnwrap(remaining(timeout, start))
            }
        }
      }

      // Recursively handle handshakes
      def handleHandshake(handshakeStatus: SSLEngineResult.HandshakeStatus, timeout: Option[FiniteDuration]): F[Unit] = F.suspend {
        val start = System.currentTimeMillis()
        handshakeStatus match {
          case SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING => F.pure(())
          case SSLEngineResult.HandshakeStatus.FINISHED => initialHandshakeDone.setPure(())
          case SSLEngineResult.HandshakeStatus.NEED_TASK =>
            runEngineTasks.flatMap { _ =>
              handleHandshake(sslEngine.getHandshakeStatus, remaining(timeout, start))
            }
          case SSLEngineResult.HandshakeStatus.NEED_WRAP =>
            runWith(writeSemaphore) {
              wrapAndWriteStep(remaining(timeout, start)) }.flatMap { handshakeStatus =>
                handleHandshake(handshakeStatus, remaining(timeout, start)) }
          case SSLEngineResult.HandshakeStatus.NEED_UNWRAP =>
            runWith(readSemaphore) {
              readAndUnwrapStep(remaining(timeout, start)) }.flatMap { handshakeStatus =>
                handleHandshake(handshakeStatus, remaining(timeout, start)) }
        }
      }

      def assertAppBytes(timeout: Option[FiniteDuration]): F[Unit] = F.suspend {
        if (appReadBuffer.remaining == 0) readAndUnwrap(timeout)
        else F.pure(())
      }

      def read0(maxBytes: Int, timeout: Option[FiniteDuration]): F[Option[fs2.Chunk[Byte]]] =
        assertAppBytes(timeout) >>
        runWith(readSemaphore) { F.delay {
          if(appReadBuffer.remaining == 0) None
          else Some(chunk(appReadBuffer, Some(maxBytes)))
        }}

      def readN0(numBytes: Int, timeout: Option[FiniteDuration]): F[Option[fs2.Chunk[Byte]]] = {

        def go(buff: ByteBuffer, timeout: Option[FiniteDuration]): F[Option[fs2.Chunk[Byte]]] = F.suspend {
          val start = System.currentTimeMillis()
          assertAppBytes(timeout).flatMap { _ =>
            runWith(readSemaphore) { F.delay {
              if(appReadBuffer.remaining == 0) {
                buff.flip()
                Some(chunk(buff))
              } else {
                val length = math.min(buff.remaining, appReadBuffer.remaining)
                buff.put(appReadBuffer.array, appReadBuffer.position, length)
                appReadBuffer.position(appReadBuffer.position + length)
                None
              }
            }}.flatMap {
              case chunk @ Some(_) => F.pure { chunk }
              case None if buff.remaining == 0 =>
                F.delay {
                  buff.flip()
                  Some(chunk(buff))
                }
              case None => go(buff, remaining(timeout, start))
            }
          }
        }

        go(ByteBuffer.allocate(numBytes), timeout)

      }

      def remaining(timeout: Option[FiniteDuration], start: Long): Option[FiniteDuration] =
        timeout.map { _ minus Duration(System.currentTimeMillis - start, MILLISECONDS) }


      new TLSSocket[F] {
        def close: F[Unit] = ???
        def endOfInput: F[Unit] = ???

        def endOfOutput: F[Unit] =
          closeOutbound0 >> socket.endOfOutput

        def localAddress: F[java.net.SocketAddress] = socket.localAddress

        def read(maxBytes: Int, timeout: Option[FiniteDuration]): F[Option[fs2.Chunk[Byte]]] =
          read0(maxBytes, timeout)

        def readN(numBytes: Int, timeout: Option[FiniteDuration]): F[Option[fs2.Chunk[Byte]]] =
          readN0(numBytes, timeout)

        // TODO, maybe make this a concrete method on Socket, since it's a default implementation
        // that works for any Socket? It's currently the same implementation as fs2.io.tcp.Socket
        def reads(maxBytes: Int, timeout: Option[FiniteDuration]): fs2.Stream[F,Byte] =
          Stream.eval(read(maxBytes,timeout)) flatMap {
            case Some(bytes) => Stream.chunk(bytes) ++ reads(maxBytes, timeout)
            case None => Stream.empty
          }

        def remoteAddress: F[java.net.SocketAddress] = socket.remoteAddress
        def write(bytes: fs2.Chunk[Byte], timeout: Option[FiniteDuration]): F[Unit] =
          write0(bytes, timeout)

        def writes(timeout: Option[FiniteDuration]): fs2.Sink[F,Byte] =
          _.chunks.flatMap { bs => Stream.eval(write(bs, timeout)) } ++ Stream.eval { endOfOutput }

        def peerCertificates: F[Option[List[Certificate]]] =
          initialHandshakeDone.get.map { _ =>
            try {
              Some(sslEngine.getSession.getPeerCertificates.toList)
            } catch {
              case _: SSLPeerUnverifiedException => None
            }
          }

      }

  }

}
