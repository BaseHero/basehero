package app.basehero.qrscan

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.util.Base64
import java.util.Random

class QrFrameDecoderTest {
    // Synthetic, not a real session: the pairing code's shape is BH1: plus
    // 122 bytes in unpadded base64url, drawn like the host's QR (level M,
    // four-module quiet zone).
    private val code = "BH1:" + Base64.getUrlEncoder().withoutPadding()
        .encodeToString(ByteArray(122).also { Random(7).nextBytes(it) })
    private val matrix: BitMatrix = QRCodeWriter().encode(code, BarcodeFormat.QR_CODE, 0, 0,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 4))

    /** A grey camera-like frame with the code drawn at [scale] pixels per module. */
    private class Frame(val width: Int, val height: Int, val stride: Int = width, val pixelStride: Int = 1) {
        val bytes = ByteArray((height - 1) * stride + (width - 1) * pixelStride + 1) { 0x80.toByte() }
        operator fun set(x: Int, y: Int, value: Int) { bytes[y * stride + x * pixelStride] = value.toByte() }
        fun plane(crop: IntArray = intArrayOf(0, 0, width, height)) =
            LumaPlane(ByteBuffer.wrap(bytes), width, height, stride, pixelStride, crop[0], crop[1], crop[2], crop[3])
    }

    private fun draw(frame: Frame, scale: Int, left: Int, top: Int, quarterTurns: Int = 0) {
        val side = matrix.width
        for (y in 0 until side * scale) for (x in 0 until side * scale) {
            var mx = x / scale
            var my = y / scale
            repeat(quarterTurns) { val t = mx; mx = side - 1 - my; my = t }
            val px = left + x
            val py = top + y
            if (px in 0 until frame.width && py in 0 until frame.height) frame[px, py] = if (matrix[mx, my]) 20 else 235
        }
    }

    @Test fun pairingCodeShapeIsTheRealOne() {
        assertEquals(167, code.length)
    }

    @Test fun decodesTheExactCodeInEveryOrientation() {
        for (turns in 0..3) {
            val frame = Frame(1280, 720)
            draw(frame, 6, 300, 100, turns)
            assertEquals("rotation ${turns * 90}", code, QrFrameDecoder.decode(frame.plane()))
        }
    }

    @Test fun honoursPaddedRowsInterleavedPixelsAndCrop() {
        // Rows padded beyond 1280 pixels at two bytes each, as some cameras lay out chroma-interleaved planes.
        val frame = Frame(1280, 720, stride = 2624, pixelStride = 2)
        draw(frame, 5, 700, 200)
        assertEquals(code, QrFrameDecoder.decode(frame.plane()))
        // The crop rectangle is where the image is; the decoder reads nothing else.
        assertEquals(code, QrFrameDecoder.decode(frame.plane(intArrayOf(640, 160, 640, 480))))
        assertNull(QrFrameDecoder.decode(frame.plane(intArrayOf(0, 0, 640, 720))))
    }

    @Test fun decodesAtSmallAndLargeModuleSizes() {
        for ((width, height, scale) in listOf(Triple(1280, 720, 3), Triple(1280, 720, 10), Triple(640, 480, 4))) {
            val frame = Frame(width, height)
            val side = matrix.width * scale
            draw(frame, scale, (width - side) / 2, (height - side) / 2)
            assertEquals("${width}x$height at $scale px/module", code, QrFrameDecoder.decode(frame.plane()))
        }
    }

    @Test fun blankNoisyAndClippedFramesDecodeNothing() {
        assertNull(QrFrameDecoder.decode(Frame(1280, 720).plane()))
        val noise = Frame(1280, 720).also { Random(3).nextBytes(it.bytes) }
        assertNull(QrFrameDecoder.decode(noise.plane()))
        // Without its finder pattern corner there is no partial or guessed result.
        val clipped = Frame(1280, 720)
        draw(clipped, 6, -60, -60)
        assertNull(QrFrameDecoder.decode(clipped.plane()))
    }

    @Test fun cropEndOverflowIsRefusedBeforeBufferAccess() {
        val plane = LumaPlane(ByteBuffer.wrap(ByteArray(4)), 2, 2, 2, 1,
            Int.MAX_VALUE, 0, 2, 1)
        assertNull(QrFrameDecoder.decode(plane))
    }

    @Test fun malformedLayoutsAreRefusedNotRead() {
        val frame = Frame(320, 240)
        draw(frame, 3, 40, 10)
        val buffer = ByteBuffer.wrap(frame.bytes)
        for (plane in listOf(
            LumaPlane(buffer, 0, 240, 320, 1, 0, 0, 0, 240),
            LumaPlane(buffer, 320, 240, 319, 1, 0, 0, 320, 240),
            LumaPlane(buffer, 320, 240, 320, 0, 0, 0, 320, 240),
            LumaPlane(buffer, 320, 241, 320, 1, 0, 0, 320, 241),
            LumaPlane(buffer, 320, 240, 320, 1, -1, 0, 320, 240),
            LumaPlane(buffer, 320, 240, 320, 1, 10, 0, 320, 240),
            LumaPlane(buffer, 320, 240, 320, 1, 0, 0, 320, 0),
            LumaPlane(ByteBuffer.wrap(frame.bytes, 0, frame.bytes.size - 1), 320, 240, 320, 1, 0, 0, 320, 240),
            LumaPlane(buffer, 100_000, 240, Int.MAX_VALUE, 1, 0, 0, 100_000, 240),
        )) assertNull(QrFrameDecoder.decode(plane))
        assertEquals(code, QrFrameDecoder.decode(LumaPlane(buffer, 320, 240, 320, 1, 0, 0, 320, 240)))
    }
}
