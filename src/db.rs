use sqlx::PgPool;
use tokio::sync::OnceCell;

static GLOBAL_POOL: OnceCell<PgPool> = OnceCell::const_new();

pub async fn init_global_pool() -> &'static PgPool {
    GLOBAL_POOL
        .get_or_init(|| async {
            PgPool::connect("postgresql://ethixion_3yc2_user:rAZxPkldDTXckuueUQuBuxn93OnU1iot@dpg-d32i7o3uibrs739s3s70-a.oregon-postgres.render.com/ethixion_3yc2?sslmode=require")
                .await
                .unwrap()
        })
        .await
}

pub fn get_global_pool() -> &'static PgPool {
    GLOBAL_POOL.get().expect("Pool not initialized")
}
