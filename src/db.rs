use sqlx::PgPool;
use tokio::sync::OnceCell;

static GLOBAL_POOL: OnceCell<PgPool> = OnceCell::const_new();

pub async fn init_global_pool() -> &'static PgPool {
    GLOBAL_POOL
        .get_or_init(|| async {
            PgPool::connect("postgres://postgres:GT@2004@localhost/ethixion")
                .await
                .unwrap()
        })
        .await
}

pub fn get_global_pool() -> &'static PgPool {
    GLOBAL_POOL.get().expect("Pool not initialized")
}
