use sqlx::PgPool;
use tokio::sync::OnceCell;

static GLOBAL_POOL: OnceCell<PgPool> = OnceCell::const_new();

pub async fn init_global_pool() -> &'static PgPool {
    GLOBAL_POOL
        .get_or_init(|| async {
            PgPool::connect("postgresql://ethixion_user:vTKEAe17u5U8u9u8Dt3kx8PErjQQIzPS@dpg-d32hrradbo4c73aerj10-a.ohio-postgres.render.com/ethixion")
                .await
                .unwrap()
        })
        .await
}

pub fn get_global_pool() -> &'static PgPool {
    GLOBAL_POOL.get().expect("Pool not initialized")
}
