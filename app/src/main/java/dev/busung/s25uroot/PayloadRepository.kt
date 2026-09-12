package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        val remoteTargets = runCatching { loadRemoteTargets() }.getOrDefault(emptyList())
        return localOverrides + remoteTargets
    }

    private fun loadRemoteTargets(): List<TargetProfile> {
        val commit = resolveMainCommit()
        val manifestBytes = downloadBytes(rawUrl(commit, "support/targets-v3.json"), MAX_MANIFEST_BYTES)
        return SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = pinArtifact(profile.exploit, commit),
            kernelSu = pinArtifact(profile.kernelSu, commit),
        ) }
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile =
        localOverrides.firstOrNull { it.matches(snapshot) }
            ?: loadTargets().firstOrNull { it.matches(snapshot) }
            ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile =
        localOverrides.firstOrNull { it.profileId == profileId }
            ?: loadTargets().firstOrNull { it.profileId == profileId }
            ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu,
            File(directory, "ksud-s25u-kdp"),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val bundled = artifact.asset?.let { path ->
            runCatching { context.assets.open(path) }.getOrNull()
        }
        val total = if (bundled != null) {
            bundled.use { input ->
                FileOutputStream(temporary).use { output -> copyInto(artifact, label, input, output) }
            }
        } else {
            val connection = open(artifact.url)
            try {
                require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
                    context.getString(R.string.repo_size_mismatch, label)
                }
                connection.inputStream.use { input ->
                    FileOutputStream(temporary).use { output -> copyInto(artifact, label, input, output) }
                }
            } finally {
                connection.disconnect()
            }
        }
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun copyInto(
        artifact: RemoteArtifact,
        label: String,
        input: InputStream,
        output: FileOutputStream,
    ): Long {
        var total = 0L
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            require(total <= artifact.size) { context.getString(R.string.repo_size_exceeded, label) }
            output.write(buffer, 0, count)
        }
        output.fd.sync()
        return total
    }

    private fun resolveMainCommit(): String {
        val response = downloadBytes(COMMIT_API_URL, MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "$RAW_REPOSITORY/$commit/$path"

    private fun pinArtifact(artifact: RemoteArtifact, commit: String): RemoteArtifact {
        if (artifact.asset != null) return artifact
        require(artifact.url.startsWith(MUTABLE_RAW_PREFIX)) {
            context.getString(R.string.repo_url_invalid)
        }
        return artifact.copy(
            url = "$RAW_REPOSITORY/$commit/${artifact.url.removePrefix(MUTABLE_RAW_PREFIX)}",
        )
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
            connect()
            require(responseCode == HttpURLConnection.HTTP_OK) { "HTTP $responseCode" }
        }

    private val localOverrides: List<TargetProfile> = listOf(
        TargetProfile(
            profileId = "dm1q-S9110ZCS8FZH3",
            displayName = "Galaxy S23 (SM-S9110) | Kernel 5.15.189",
            models = setOf("SM-S9110"),
            kernelVersions = setOf("5.15.189"),
            exploit = RemoteArtifact(
                url = "$MUTABLE_RAW_PREFIX/artifacts/dm1q-S9110ZCS8FZH3/cve-2026-43499-app.so",
                size = 104128,
                asset = "payloads/cve-2026-43499-app.so",
            ),
            kernelSu = RemoteArtifact(
                url = "$MUTABLE_RAW_PREFIX/kernelsu/ksud-dm3q-S918BXXSAFZF5-kdp",
                size = 4879560,
                asset = "payloads/ksud-s25u-kdp",
            ),
        ),
    )

    companion object {
        private const val COMMIT_API_URL =
            "https://api.github.com/repos/BuSung-dev/Root-My-Galaxy-Payloads/git/ref/heads/main"
        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/BuSung-dev/Root-My-Galaxy-Payloads"
        private const val MUTABLE_RAW_PREFIX = "$RAW_REPOSITORY/main/"
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        private const val MAX_MANIFEST_BYTES = 256 * 1024
    }
}
