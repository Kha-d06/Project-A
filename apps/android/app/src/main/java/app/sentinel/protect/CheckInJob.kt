package app.sentinel.protect

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import java.util.concurrent.Executors

/**
 * Checks in with the Qalaa account every 15 minutes (Android's shortest
 * period for background work), runs any scans started from the website, and
 * keeps the malware fingerprints fresh. Survives restarts (persisted job).
 */
class CheckInJob : JobService() {
    companion object {
        private const val JOB_ID = 4201
        private val worker = Executors.newSingleThreadExecutor()

        fun schedule(context: Context) {
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, CheckInJob::class.java))
                .setPeriodic(15 * 60 * 1000L)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(true)
                .build()
            scheduler.schedule(job)
        }

        fun cancel(context: Context) {
            context.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
        }
    }

    override fun onStartJob(params: JobParameters): Boolean {
        worker.execute {
            val engine = Engine.get(this)
            try {
                if (engine.signaturesAge() > 24 * 3600_000L) runCatching { engine.updateSignatures() }
                engine.checkIn()
            } finally {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true
}
