package generate;

import java.io.Serializable;
import java.util.Date;
import lombok.Data;

/**
 * sys_menu
 * @author 
 */
@Data
public class SysMenu implements Serializable {
    /**
     * 主键
     */
    private Long id;

    /**
     * 名称
     */
    private String name;

    /**
     * 菜单类型（0=目录，1=插件，2=虚拟页面）
     */
    private Integer type;

    /**
     * 内容
     */
    private String content;

    /**
     * 父目录
     */
    private Long parentId;

    /**
     * 启动参数
     */
    private String parameter;

    /**
     * 创建者
     */
    private Long createBy;

    /**
     * 创建时间
     */
    private Date createTime;

    /**
     * 更新者
     */
    private Long updateBy;

    /**
     * 更新时间
     */
    private Date updateTime;

    /**
     * 持久
     */
    private Boolean persistent;

    /**
     * 图标
     */
    private String icon;

    /**
     * 隐藏
     */
    private Boolean hidden;

    /**
     * 自启动
     */
    private Boolean startup;

    /**
     * 状态
     */
    private Integer status;

    /**
     * 排序
     */
    private Integer orderIndex;

    private static final long serialVersionUID = 1L;
}