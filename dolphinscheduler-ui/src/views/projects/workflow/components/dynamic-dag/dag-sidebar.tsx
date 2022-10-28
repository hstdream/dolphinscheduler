/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { defineComponent, onMounted, toRefs } from 'vue'
import { useSidebar } from './use-sidebar'
import styles from './dag-sidebar.module.scss'

const DagSidebar = defineComponent({
  name: 'DagSidebar',
  emits: ['Dragend'],
  setup(props, context) {
    const { variables, getTaskList } = useSidebar()

    const handleDragend = (e: DragEvent, task: any) => {
      context.emit('Dragend', e, task)
    }

    onMounted(() => {
      getTaskList()
    })

    return {
      ...toRefs(variables),
      handleDragend
    }
  },
  render() {
    return (
      <div>
        {
          this.taskList.map(task => {
            return (
              <div class={styles['task-item']} draggable='true' onDragend={(e: DragEvent) => this.handleDragend(e, task)}>
                {task}
              </div>
            )
          })
        }
      </div>
    )
  }
})

export { DagSidebar }